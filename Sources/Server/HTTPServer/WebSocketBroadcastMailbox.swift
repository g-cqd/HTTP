//
//  WebSocketBroadcastMailbox.swift
//  HTTPServer
//
//  Per-connection bounded delivery for hub broadcasts (2026-07-31 audit, finding 1).
//
//  Broadcasts and inbound transport octets used to share one `.bufferingNewest(256)` stream, which is
//  wrong in both directions. Transport octets must never be dropped — losing one desynchronizes the
//  resumable frame parser, corrupting framing rather than merely losing a message — and they now go
//  through `BoundedByteChannel`. Broadcasts, in the other direction, must never *block*: the hub sink
//  is a synchronous non-suspending closure invoked while the hub holds its own isolation, so it cannot
//  wait for a slow connection.
//
//  That leaves the only correct policy for this half: a bounded ring with an explicit, *counted*
//  drop. A connection that fell behind is closed with `1008` (RFC 6455 §7.4.1) rather than silently
//  serving it an incomplete view of the topic.
//
//  The ring is bounded twice, by count AND by retained octets (2026-07-31 performance addendum). A
//  count alone bounds nothing that matters: at the default `effectiveWebSocketMessageSize`, the
//  default 64 queued broadcasts is unbounded memory per connection (CWE-770). The byte accounting is
//  `BoundedByteChannel`'s, but *not* its parking — the hub sink is a synchronous closure invoked
//  inside the hub's own isolation and cannot wait on a slow connection — so crossing the watermark
//  evicts rather than blocks, and every eviction stays counted and visible exactly as before.
//
//  The wakeup edge is coalesced: at most one `.broadcastReady` ticket is outstanding at a time, so a
//  publish storm cannot inflate the pump's mailbox no matter how fast it arrives.
//

internal import HTTPCore
internal import Synchronization
internal import WebSocket

/// A fixed-capacity, drop-oldest broadcast queue for one WebSocket connection.
final class WebSocketBroadcastMailbox: Sendable {
    /// What ``deposit(_:signal:)`` did with the message.
    enum Deposit: Sendable, Equatable {
        case enqueued
        /// The ring was full: the oldest queued message was evicted to make room.
        case droppedOldest
    }

    /// One queued broadcast with its octet cost, so eviction can debit what it actually released.
    ///
    /// Measured once, on deposit. Recomputing on eviction would charge an O(n) `utf8.count` walk to
    /// the eviction path, which is the path a flooding publisher already drives hardest.
    private struct Entry {
        let message: WebSocketMessage
        let bytes: Int
    }

    private struct State {
        var slots: [Entry?]
        var head = 0
        var queued = 0
        /// Octets currently retained by queued messages — the bound a count cannot express.
        var bytes = 0
        /// Whether a `.broadcastReady` ticket is already outstanding — the coalescing edge.
        var signalled = false
        var dropped = 0
    }

    private let capacity: Int
    private let maxBytes: Int
    private let state: Mutex<State>

    /// Creates a mailbox holding at most `capacity` undelivered broadcasts and `maxBytes` of them.
    ///
    /// Both bounds are live at once and either can trigger the drop-oldest eviction. No default for
    /// `maxBytes`: a queue that invents its own memory bound is how the count-only bound this
    /// replaces came to be believed.
    init(capacity: Int, maxBytes: Int) {
        let bounded = max(1, capacity)
        self.capacity = bounded
        self.maxBytes = max(1, maxBytes)
        state = Mutex(State(slots: [Entry?](repeating: nil, count: bounded)))
    }

    /// Enqueues `message`, evicting the oldest when full, and raises the wakeup edge if it was down.
    ///
    /// Never suspends: the hub sink runs inside the hub's isolation and cannot wait on a connection.
    /// `signal` is invoked *outside* the lock, and only on the rising edge — so the pump's mailbox
    /// holds at most one outstanding ticket regardless of publish rate.
    ///
    /// Either bound can trigger the eviction: the ring evicts until the newcomer fits under *both*
    /// the slot count and the octet watermark. A message larger than the whole watermark is still
    /// accepted, against an emptied ring — refusing it would leave the queue empty AND the message
    /// lost, and the connection is being closed either way. Retention is therefore bounded by
    /// `maxBytes + one maximum message`, itself capped by `effectiveWebSocketMessageSize`.
    ///
    /// - Returns: whether a message had to be evicted. Evictions are also accumulated in
    ///   ``droppedCount``, which the pump inspects and turns into a `1008` close; a drop is therefore
    ///   never invisible, which is the property the audit requires of this half — and evicting on
    ///   octets rather than only on slots does not weaken it, because both routes count.
    @discardableResult
    func deposit(_ message: WebSocketMessage, signal: @Sendable () -> Void) -> Deposit {
        let cost = Self.byteCount(of: message)
        let (outcome, raisedEdge) = state.withLock { state -> (Deposit, Bool) in
            var evicted = false
            while state.queued == capacity || (state.queued > 0 && state.bytes + cost > maxBytes) {
                Self.evictOldest(from: &state, capacity: capacity)
                evicted = true
            }
            state.slots[(state.head + state.queued) % capacity] = Entry(
                message: message, bytes: cost
            )
            state.queued += 1
            state.bytes += cost
            let raisedEdge = !state.signalled
            state.signalled = true
            return (evicted ? .droppedOldest : .enqueued, raisedEdge)
        }
        if raisedEdge {
            signal()
        }
        return outcome
    }

    /// Takes every queued message and lowers the wakeup edge.
    ///
    /// Clearing the edge and draining happen in one critical section, so a deposit racing this either
    /// lands before the drain (and is returned) or after it (and raises a fresh edge). Neither can
    /// strand a message.
    func drain() -> [WebSocketMessage] {
        state.withLock { state in
            state.signalled = false
            guard state.queued > 0 else {
                return []
            }
            var messages: [WebSocketMessage] = []
            messages.reserveCapacity(state.queued)
            for offset in 0 ..< state.queued {
                if let entry = state.slots[(state.head + offset) % capacity] {
                    messages.append(entry.message)
                }
                state.slots[(state.head + offset) % capacity] = nil
            }
            state.head = 0
            state.queued = 0
            state.bytes = 0
            return messages
        }
    }

    /// Broadcasts evicted because this connection could not keep up.
    ///
    /// Non-zero means the peer's view of the topic has a hole, which the pump turns into a `1008`
    /// close (RFC 6455 §7.4.1) rather than continuing to serve an incomplete stream.
    var droppedCount: Int { state.withLock(\.dropped) }

    /// Undelivered messages currently queued (metrics and tests).
    var queuedCount: Int { state.withLock(\.queued) }

    /// Octets retained by undelivered messages (metrics and tests).
    var queuedBytes: Int { state.withLock(\.bytes) }

    /// Drops the oldest queued entry, debiting both bounds and counting the loss.
    private static func evictOldest(from state: inout State, capacity: Int) {
        state.bytes -= state.slots[state.head]?.bytes ?? 0
        state.slots[state.head] = nil
        state.head = (state.head + 1) % capacity
        state.queued -= 1
        state.dropped += 1
    }

    /// The payload octets `message` retains.
    ///
    /// Payload only: the enum and array headers are a small constant per message, and it is the
    /// *count* bound that exists to cap per-message constant overhead. `utf8.count` is O(1) for a
    /// native Swift string's contiguous UTF-8 storage.
    private static func byteCount(of message: WebSocketMessage) -> Int {
        switch message {
            case .text(let string):
                string.utf8.count
            case .binary(let bytes):
                bytes.count
        }
    }

    deinit {
        // No teardown beyond ARC.
    }
}
