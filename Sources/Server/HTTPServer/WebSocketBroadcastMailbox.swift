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

    private struct State {
        var slots: [WebSocketMessage?]
        var head = 0
        var queued = 0
        /// Whether a `.broadcastReady` ticket is already outstanding — the coalescing edge.
        var signalled = false
        var dropped = 0
    }

    private let capacity: Int
    private let state: Mutex<State>

    /// Creates a mailbox holding at most `capacity` undelivered broadcasts.
    init(capacity: Int) {
        let bounded = max(1, capacity)
        self.capacity = bounded
        state = Mutex(State(slots: [WebSocketMessage?](repeating: nil, count: bounded)))
    }

    /// Enqueues `message`, evicting the oldest when full, and raises the wakeup edge if it was down.
    ///
    /// Never suspends: the hub sink runs inside the hub's isolation and cannot wait on a connection.
    /// `signal` is invoked *outside* the lock, and only on the rising edge — so the pump's mailbox
    /// holds at most one outstanding ticket regardless of publish rate.
    ///
    /// - Returns: whether a message had to be evicted. Evictions are also accumulated in
    ///   ``droppedCount``, which the pump inspects and turns into a `1008` close; a drop is therefore
    ///   never invisible, which is the property the audit requires of this half.
    @discardableResult
    func deposit(_ message: WebSocketMessage, signal: @Sendable () -> Void) -> Deposit {
        let (outcome, raisedEdge) = state.withLock { state -> (Deposit, Bool) in
            var outcome = Deposit.enqueued
            if state.queued == capacity {
                state.slots[state.head] = nil
                state.head = (state.head + 1) % capacity
                state.queued -= 1
                state.dropped += 1
                outcome = .droppedOldest
            }
            state.slots[(state.head + state.queued) % capacity] = message
            state.queued += 1
            let raisedEdge = !state.signalled
            state.signalled = true
            return (outcome, raisedEdge)
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
                if let message = state.slots[(state.head + offset) % capacity] {
                    messages.append(message)
                }
                state.slots[(state.head + offset) % capacity] = nil
            }
            state.head = 0
            state.queued = 0
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

    deinit {
        // No teardown beyond ARC.
    }
}
