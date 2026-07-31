//
//  HTTP3StreamRegistry.swift
//  HTTPServer
//
//  The per-connection HTTP/3 stream registry (audit addendum P0.3). QUIC delivers bytes per stream, so
//  the server reads each stream on its own task — but the sans-I/O ``HTTP3Connection`` engine is a
//  *connection*-scoped state machine whose output is addressed by stream id and need not belong to the
//  stream whose bytes provoked it. RFC 9204 §2.1.2 makes that routine: a request whose QPACK field
//  section references a not-yet-received insert is buffered, and it surfaces later from the **encoder
//  stream's** receive.
//
//  This registry is the routing table that makes such output land on the right stream: id → writer,
//  a claim latch so a request is dispatched to the responder exactly once, and a bounded per-stream
//  mailbox for the routed events that only the owning stream's task — or, once that task has ended,
//  the connection dispatcher — can act on.
//
//  The mailbox is the ONLY place a routed event is ever held (audit REG-1). It is bounded in retained
//  *octets* as well as in messages, because these events carry request bodies and tunnel payloads and
//  a message count bounds nothing; and it is lossless — a deposit past the bound is refused so the
//  caller resets the stream (RFC 9114 §8.1 H3_EXCESSIVE_LOAD), never trimmed. Dropping a `request` or
//  a body chunk is not a throttle, it is a correctness fault: the peer gets neither a response nor a
//  reset, and a resumable body loses octets mid-stream.
//
//  The dispatcher is told about an orphaned stream through a payload-free ticket channel rather than by
//  carrying batches, and a ticket is yielded only on the entry's no-ticket → ticket transition. That is
//  what makes the channel *provably* bounded — at most one outstanding ticket per registered stream —
//  so it needs no drop policy of its own.
//
//  Standards: RFC 9114 §6 (stream roles), §8.1 (error codes), RFC 9204 §2.1.2 (blocked streams),
//  RFC 9204 §3.2.1 (field-line sizing, reused for the octet bound); CWE-770.
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport
internal import Synchronization

/// The live streams of one HTTP/3 connection: their writers, their dispatch latch, and their mailboxes.
///
/// Thread-safe and synchronous — one `Mutex`, no `await` — so a stream task can consult it between two
/// engine calls without adding an isolation hop to the request path.
final class HTTP3StreamRegistry: Sendable {
    /// What depositing routed events for a stream did.
    enum Deposit {
        /// The events are queued, and whoever must act on them has been woken.
        ///
        /// The stream's own task if it is still reading (through its ``HTTP3StreamInbox``), else the
        /// connection dispatcher (through its ticket channel).
        case queued
        /// The stream is not registered — it was reset, retired, or never opened.
        ///
        /// Nothing can be delivered on it and nothing is retained; QUIC has no way to reach it.
        case unknown
        /// The mailbox is at its retained-octet or message bound.
        ///
        /// The caller must reset the stream rather than grow it, and must not drop the events: this
        /// fails closed (RFC 9114 §8.1 H3_EXCESSIVE_LOAD, CWE-770).
        case overflow(any QUICStream)
    }

    /// One registered stream.
    private struct Entry {
        let stream: any QUICStream
        /// Whether a per-stream task is still reading this stream's inbound bytes.
        var isDriving = true
        /// Whether a request on this stream has already been handed to the responder (emit-once).
        var isClaimed = false
        /// Routed events the owning task must act on itself (it holds the tunnel / body-feed state).
        var mailbox: [HTTP3Connection.Event] = []
        /// The octets ``mailbox`` retains, maintained on every append and drain (audit REG-1).
        ///
        /// A running total rather than a fold over the queue: the bound is checked on every deposit,
        /// which is a peer-driven path, so it must be O(1).
        var mailboxBytes = 0
        /// Whether the connection dispatcher already holds an undrained ticket for this stream.
        ///
        /// One ticket at a time per stream is what bounds the dispatcher's channel without a drop
        /// policy: the ticket says "there is mail", and the dispatcher drains the whole mailbox.
        var hasTicket = false
        /// The owning task's merged wakeup mailbox, signalled on every deposit (audit REG-2).
        ///
        /// Optional because the stream is registered on the connection's accept loop, one hop before
        /// its serve task exists; a deposit that lands in that window is picked up by
        /// ``attach(_:to:)``, which signals immediately when the mailbox is already non-empty.
        var inbox: HTTP3StreamInbox?
        /// The ``DispatchPlan`` this stream's HEADERS resolved — its responder generation and its route
        /// match — filed by the engine's `resolveRoute` and taken again at dispatch.
        ///
        /// It lives on the entry rather than in a table of its own precisely so it inherits this
        /// registry's lifetime: `retire`/`endDriving` already drop an entry on every path a stream can
        /// end, and a second table keyed by a peer-chosen stream id would be a second set of paths to
        /// remember (CWE-770).
        var plan: DispatchPlan?

        /// Whether a deposit of `count` events and `bytes` octets stays within the mailbox bounds.
        ///
        /// A deposit into an empty mailbox always fits, however large: one engine hand-off is already
        /// bounded by the engine's own connection-wide buffered-body budget, so re-bounding it here
        /// could only refuse a legitimate request. What is bounded is accumulation across hand-offs.
        func accepts(_ count: Int, _ bytes: Int, within budget: Int) -> Bool {
            mailbox.isEmpty
                || (mailboxBytes + bytes <= budget
                    && mailbox.count + count <= HTTP3StreamRegistry.mailboxCapacity)
        }

        /// Resolves who to wake for a fresh deposit, latching the dispatcher ticket when one is owed.
        ///
        /// Nothing to wake while the stream is driving but its serve task has not attached its inbox
        /// yet — ``attach(_:to:)`` covers that window — or while the dispatcher already holds an
        /// undrained ticket, which is the invariant that bounds its channel.
        mutating func claimWakeup(_ id: QUICStreamID) -> Wakeup {
            guard !isDriving else {
                return inbox.map(Wakeup.owner) ?? .none
            }
            guard !hasTicket else {
                return .none
            }
            hasTicket = true
            return .dispatcher(id)
        }

        /// Empties the mailbox, returning its contents and releasing the dispatcher's ticket.
        mutating func drainMailbox() -> [HTTP3Connection.Event] {
            let queued = mailbox
            mailbox.removeAll(keepingCapacity: false)
            mailboxBytes = 0
            hasTicket = false
            return queued
        }
    }

    /// Who must be told a stream's mailbox changed — resolved under the lock, delivered outside it.
    private enum Wakeup {
        case none
        case owner(HTTP3StreamInbox)
        case dispatcher(QUICStreamID)
    }

    /// The most routed events one stream may hold before the stream is reset instead.
    ///
    /// The engine only routes events across streams when it unblocks a QPACK-blocked section
    /// (RFC 9204 §2.1.2), and it caps blocked streams at `SETTINGS_QPACK_BLOCKED_STREAMS`, so a
    /// well-behaved peer never approaches this; it exists so a misbehaving one cannot grow the queue.
    ///
    /// A *second*, independent bound alongside ``mailboxByteBudget`` — this one caps the per-event
    /// bookkeeping a peer can force, the byte budget caps the memory.
    static let mailboxCapacity = 64

    /// The octets one stream's mailbox may accumulate before a further deposit is refused.
    ///
    /// In retained octets, not messages: these events carry request bodies (RFC 9114 §4.1) and tunnel
    /// payloads (RFC 9220), so a message count bounds nothing.
    ///
    /// A deposit into an *empty* mailbox is always accepted however large it is. One engine hand-off
    /// is already bounded by the engine's own connection-wide buffered-body budget, so re-bounding it
    /// here could only refuse a legitimate request; what this bounds is *accumulation* across
    /// hand-offs, which nothing else does.
    private let mailboxByteBudget: Int

    private let entries = Mutex<[QUICStreamID: Entry]>([:])
    /// The connection dispatcher's ticket channel — where a stream whose own task has ended is
    /// announced, by id only (audit REG-1).
    private let dispatcher = Mutex<AsyncStream<QUICStreamID>.Continuation?>(nil)

    /// Creates a registry whose per-stream mailboxes accumulate at most `mailboxByteBudget` octets.
    init(mailboxByteBudget: Int) {
        self.mailboxByteBudget = max(1, mailboxByteBudget)
    }

    deinit {
        // No teardown beyond ARC; the streams themselves are owned by the QUIC connection.
    }

    /// Registers a freshly opened peer stream, with its task about to start reading it.
    func register(_ stream: any QUICStream) {
        entries.withLock { $0[stream.id] = Entry(stream: stream) }
    }

    /// The writer registered for `id`, or nil once the stream has been retired.
    func writer(for id: QUICStreamID) -> (any QUICStream)? {
        entries.withLock { $0[id]?.stream }
    }

    /// Latches `id` as dispatched and returns its writer, or nil if it is unknown or already claimed.
    ///
    /// This is the exactly-once guarantee for the responder: the buffered path and the routed path can
    /// both see a request for the same stream, and only the first of them may run the handler.
    func claim(_ id: QUICStreamID) -> (any QUICStream)? {
        entries.withLock { current in
            guard var entry = current[id], !entry.isClaimed else {
                return nil
            }
            entry.isClaimed = true
            current[id] = entry
            return entry.stream
        }
    }

    /// Registers the owning task's merged wakeup mailbox, so a deposit can wake it (audit REG-2).
    ///
    /// Signals at once when mail already arrived in the window between ``register(_:)`` and the serve
    /// task starting — otherwise that deposit's wakeup would be lost and the stream would park until
    /// its read deadline.
    func attach(_ inbox: HTTP3StreamInbox, to id: QUICStreamID) {
        let owed = entries.withLock { current -> Bool in
            guard var entry = current[id] else {
                return false
            }
            entry.inbox = inbox
            current[id] = entry
            return !entry.mailbox.isEmpty
        }
        if owed {
            inbox.signalRouted()
        }
    }

    /// Registers the connection dispatcher's ticket channel (audit REG-1).
    ///
    /// Held here rather than threaded through every routing call site, because "where does output for
    /// this stream go" is exactly what this type answers — and it is what lets a deposit decide between
    /// waking the owner and ticketing the dispatcher without the caller knowing which.
    func attachDispatcher(_ continuation: AsyncStream<QUICStreamID>.Continuation) {
        dispatcher.withLock { $0 = continuation }
    }

    /// Queues `events` for whoever owns the stream, and wakes them.
    ///
    /// This is the ONLY place a routed event is retained, and the deposit is lossless: it either queues
    /// the whole batch or refuses it as ``Deposit/overflow(_:)`` for the caller to escalate.
    ///
    /// It cannot park instead of refusing. The caller is a *stream task*, one statement after its own
    /// `engine.receive` returned; suspending it on another stream's application progress would be
    /// cross-stream head-of-line blocking — the thing HTTP/3 exists to remove — and can deadlock, since
    /// the consumer it would wait on may itself be a stream task parked depositing here. So it fails
    /// closed, exactly as ``BoundedByteChannel/trySend(_:)`` does for the HTTP/2 serve loop.
    ///
    /// The wakeup is the other half (audit REG-2): a still-reading owner may be parked with no further
    /// request bytes coming, and a QPACK-unblocked field section (RFC 9204 §2.1.2) is precisely the work
    /// that arrives without any.
    func deposit(_ events: [HTTP3Connection.Event], for id: QUICStreamID) -> Deposit {
        let added = events.reduce(0) { $0 + Self.retainedBytes(of: $1) }
        let (outcome, wakeup) = entries.withLock { current -> (Deposit, Wakeup) in
            guard var entry = current[id] else {
                return (.unknown, .none)
            }
            guard entry.accepts(events.count, added, within: mailboxByteBudget) else {
                return (.overflow(entry.stream), .none)
            }
            entry.mailbox.append(contentsOf: events)
            entry.mailboxBytes += added
            let owed = entry.claimWakeup(id)
            current[id] = entry
            return (.queued, owed)
        }
        // Signalled outside the lock: whoever is woken consults this same registry immediately.
        deliver(wakeup)
        return outcome
    }

    /// Delivers a resolved wakeup, outside the lock that resolved it.
    private func deliver(_ wakeup: Wakeup) {
        switch wakeup {
            case .none:
                break
            case .owner(let inbox):
                inbox.signalRouted()
            case .dispatcher(let id):
                dispatcher.withLock(\.self)?.yield(id)
        }
    }

    /// The octets a routed event retains, for the mailbox's byte bound (CWE-770).
    ///
    /// Field sections are measured with the RFC 9204 §3.2.1 entry sizing (name + value + 32) — the same
    /// accounting `maxHeaderListSize` already bounds a decoded section by — so the two budgets agree.
    private static func retainedBytes(of event: HTTP3Connection.Event) -> Int {
        switch event {
            case .request(_, let request, let body):
                Self.retainedBytes(of: request) + body.count
            case .requestHead(_, let request):
                Self.retainedBytes(of: request)
            case .extendedConnect(_, let request, let proto):
                Self.retainedBytes(of: request) + proto.utf8.count
            case .requestBodyChunk(_, let bytes), .tunnelData(_, let bytes):
                bytes.count
            case .requestEnd, .tunnelClosed, .goAway:
                0
        }
    }

    /// The octets a decoded request head retains (RFC 9204 §3.2.1 sizing over its field lines).
    private static func retainedBytes(of request: HTTPRequest) -> Int {
        var total = request.path.utf8.count
        total += request.scheme?.utf8.count ?? 0
        total += request.authority?.utf8.count ?? 0
        for field in request.headerFields {
            total += field.name.canonicalName.utf8.count + field.value.utf8.count + 32
        }
        return total
    }

    /// Files the plan a stream's head resolved, for its dispatch to take back.
    ///
    /// Audit CR-F12 / CR-F19: one route match and one responder generation per request.
    ///
    /// A no-op for a stream that is not registered — it was reset or retired while its HEADERS were
    /// still decoding, and nothing will dispatch it.
    func file(_ plan: DispatchPlan, for id: QUICStreamID) {
        entries.withLock { $0[id]?.plan = plan }
    }

    /// The plan filed for `id`, or `nil` if its head never resolved one.
    func plan(for id: QUICStreamID) -> DispatchPlan? {
        entries.withLock { $0[id]?.plan }
    }

    /// Drains the routed events queued for `id` (empty when there are none).
    ///
    /// Releases the dispatcher's ticket in the same critical section as the drain, so a deposit that
    /// lands immediately afterwards ticket it again rather than finding a stale one outstanding.
    func takeMailbox(_ id: QUICStreamID) -> [HTTP3Connection.Event] {
        entries.withLock { current in
            guard var entry = current[id], !entry.mailbox.isEmpty else {
                return []
            }
            let queued = entry.drainMailbox()
            current[id] = entry
            return queued
        }
    }

    /// Notes that the task reading `id` has stopped.
    ///
    /// The entry is retired unless the engine still owes the stream output — a QPACK-blocked section
    /// whose request has not surfaced yet (RFC 9204 §2.1.2).
    ///
    /// Retaining only the blocked streams is what keeps the registry bounded: a long-lived connection
    /// that opens streams sequentially retires each as its task ends, and the engine's own
    /// `SETTINGS_QPACK_BLOCKED_STREAMS` cap bounds the retained remainder.
    ///
    /// A retained entry keeps whatever is already in its mailbox and hands it to the dispatcher
    /// (audit REG-1): a deposit can land in the instant between the last drain and this call, and
    /// clearing the queue here — as it used to — would drop exactly that batch.
    func endDriving(_ id: QUICStreamID, retain: Bool) {
        let wakeup = entries.withLock { current -> Wakeup in
            guard retain else {
                current[id] = nil
                return .none
            }
            guard var entry = current[id] else {
                return .none
            }
            entry.isDriving = false
            entry.inbox = nil  // its serve loop is gone; the dispatcher owns the stream now
            let owed = entry.mailbox.isEmpty ? Wakeup.none : entry.claimWakeup(id)
            current[id] = entry
            return owed
        }
        deliver(wakeup)
    }

    /// Drops `id` — its response was written, or it was reset.
    func retire(_ id: QUICStreamID) {
        entries.withLock { $0[id] = nil }
    }

    /// Every registered writer, for a connection-wide sweep (a forced shutdown close).
    func allStreams() -> [any QUICStream] {
        entries.withLock { current in current.values.map(\.stream) }
    }

    /// The number of streams currently registered.
    var count: Int {
        entries.withLock(\.count)
    }

    /// Whether no stream is registered — every one this connection saw has been retired.
    var isEmpty: Bool {
        entries.withLock(\.isEmpty)
    }
}
