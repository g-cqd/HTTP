//
//  HTTP2ConsumptionSignal.swift
//  HTTPServer
//
//  The handler → serve-loop half of consumption-gated HTTP/2 flow control (2026-07-31 audit F2/F4,
//  ADR 0006).
//
//  The engine debits a gated stream's receive window as the peer sends and credits it back only as the
//  *handler* takes each chunk. Those two events happen on different tasks, and the constraint that
//  shapes this type is that they must stay that way: the serve loop is the engine's single owner and
//  can never block on a handler (it would then be unable to process the WINDOW_UPDATE that unblocks the
//  connection — the deadlock ADR 0006's blocking analysis calls out), and the handler must never touch
//  the engine.
//
//  So the handler reports into a lock-free counter and pokes the mailbox; the serve loop drains the
//  counter when it processes that poke and issues the WINDOW_UPDATE itself. Neither side ever waits for
//  the other.
//

internal import Synchronization

/// A per-stream, handler → serve-loop byte-consumption report (ADR 0006).
///
/// The handler never blocks and never touches the engine; the serve loop — the engine's single owner —
/// drains this and issues the WINDOW_UPDATE.
final class HTTP2ConsumptionSignal: Sendable {
    /// Octets the handler has taken and the serve loop has not yet credited.
    private let bytes = Atomic<Int>(0)
    /// Whether a mailbox wakeup is already outstanding for this stream — the coalescing edge.
    private let signalled = Atomic<Bool>(false)
    /// Yields `.consumed(streamID)` into the connection's mailbox.
    private let notify: @Sendable () -> Void

    /// Creates a signal that pokes the serve loop through `notify`.
    ///
    /// - Parameter notify: yields this stream's `.consumed` wakeup into the connection mailbox. Called
    ///   only on the rising edge, so a handler draining a large body at chunk granularity produces one
    ///   wakeup per serve-loop turn rather than one per chunk.
    init(notify: @escaping @Sendable () -> Void) {
        self.notify = notify
    }

    /// Records `count` consumed octets, waking the serve loop if it is not already due to look.
    ///
    /// `.relaxed` is sufficient for the accumulate. This is a genuinely independent SPSC counter — one
    /// handler adds, one serve loop drains, and *nothing else is published through it*: the octets
    /// themselves travelled through the ``BoundedByteChannel``, which did its own synchronization, so
    /// this value orders no other memory and needs no fence to carry any.
    func record(_ count: Int) {
        guard count > 0 else {
            return
        }
        bytes.wrappingAdd(count, ordering: .relaxed)
        if !signalled.exchange(true, ordering: .relaxed) {
            notify()
        }
    }

    /// Takes every octet recorded so far, re-arming the wakeup edge.
    ///
    /// Clear-then-drain is what makes the coalesced edge lossless: a ``record(_:)`` that lands between
    /// the two lines finds `signalled` already false and posts a *fresh* wakeup, so its bytes are either
    /// included in this drain or announced by that next one — never both, never neither. Draining first
    /// would leave exactly that interleaving with bytes banked and no wakeup pending, and the stream
    /// would sit on credit it had already earned until some unrelated event happened to wake the loop.
    ///
    /// The drain uses `.acquiringAndReleasing` so the zeroing is published to the next `record(_:)` and
    /// cannot be reordered above the mailbox dequeue that motivated it.
    func takeAll() -> Int {
        signalled.store(false, ordering: .relaxed)
        return bytes.exchange(0, ordering: .acquiringAndReleasing)
    }

    deinit {
        // No teardown beyond ARC.
    }
}
