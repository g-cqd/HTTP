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
//  mailbox for the routed events that only the owning stream's task can act on.
//
//  Standards: RFC 9114 §6 (stream roles), RFC 9204 §2.1.2 (blocked streams); the mailbox bound is a
//  CWE-770 (allocation without limits) defense on a peer-driven queue.
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
        /// The stream's task is still reading it; the events are queued for that task to drain.
        case queued
        /// No task is reading the stream any more (its FIN or EOF was seen): the dispatcher owns them.
        case orphaned(any QUICStream)
        /// The stream is not registered — it was reset, retired, or never opened.
        case unknown
        /// The mailbox is full; the caller must reset the stream rather than grow it (CWE-770).
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
    }

    /// The most routed events one stream may hold before the stream is reset instead.
    ///
    /// The engine only routes events across streams when it unblocks a QPACK-blocked section
    /// (RFC 9204 §2.1.2), and it caps blocked streams at `SETTINGS_QPACK_BLOCKED_STREAMS`, so a
    /// well-behaved peer never approaches this; it exists so a misbehaving one cannot grow the queue.
    static let mailboxCapacity = 64

    private let entries = Mutex<[QUICStreamID: Entry]>([:])

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

    /// Hands `events` to the stream that owns them, reporting who must act on them.
    func deposit(_ events: [HTTP3Connection.Event], for id: QUICStreamID) -> Deposit {
        entries.withLock { current in
            guard var entry = current[id] else {
                return .unknown
            }
            guard entry.isDriving else {
                return .orphaned(entry.stream)
            }
            guard entry.mailbox.count + events.count <= Self.mailboxCapacity else {
                return .overflow(entry.stream)
            }
            entry.mailbox.append(contentsOf: events)
            current[id] = entry
            return .queued
        }
    }

    /// Drains the routed events queued for `id` (empty when there are none).
    func takeMailbox(_ id: QUICStreamID) -> [HTTP3Connection.Event] {
        entries.withLock { current in
            guard var entry = current[id], !entry.mailbox.isEmpty else {
                return []
            }
            let queued = entry.mailbox
            entry.mailbox.removeAll(keepingCapacity: false)
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
    func endDriving(_ id: QUICStreamID, retain: Bool) {
        entries.withLock { current in
            guard retain else {
                current[id] = nil
                return
            }
            current[id]?.isDriving = false
            current[id]?.mailbox.removeAll(keepingCapacity: false)
        }
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
}
