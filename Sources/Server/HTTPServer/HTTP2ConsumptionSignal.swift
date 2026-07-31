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
//  The coalesced wakeup edge makes the two sides a store-buffer pair, which is why the orderings here
//  are sequentially consistent rather than relaxed — see ``HTTP2ConsumptionSignal/takeAll()``.
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
    /// This counter publishes no other memory — the octets themselves travelled through the
    /// ``BoundedByteChannel``, which did its own synchronization — so nothing here needs *acquire* or
    /// *release* semantics. What it does need is **store-load** ordering against ``takeAll()``, which is
    /// strictly stronger than release/acquire can express: see that method.
    func record(_ count: Int) {
        guard count > 0 else {
            return
        }
        bytes.wrappingAdd(count, ordering: .sequentiallyConsistent)
        if !signalled.exchange(true, ordering: .sequentiallyConsistent) {
            notify()
        }
    }

    /// Takes every octet recorded so far, re-arming the wakeup edge.
    ///
    /// Clear-then-drain is what makes the coalesced edge lossless: a ``record(_:)`` that lands between
    /// the two lines finds `signalled` already false and posts a *fresh* wakeup, so its bytes are either
    /// included in this drain or announced by that next one. Draining first would leave exactly that
    /// interleaving with bytes banked behind a lowered edge, and the stream would sit on credit it had
    /// already earned until some unrelated event happened to wake the loop.
    ///
    /// **Why sequential consistency, not relaxed.** The two sides are the store-buffer (SB / Dekker)
    /// litmus test across two independent locations: this one stores `signalled` then reads `bytes`, the
    /// other writes `bytes` then reads `signalled`. Relaxed — and release/acquire alike — permit *both*
    /// reads to miss the other's write, and on arm64 that is not theoretical. The resulting interleaving
    /// is a permanently lost wakeup: the handler's octets stay banked with no wakeup outstanding, and
    /// since the peer is by then stalled on a closed window, nothing else will ever wake the loop for
    /// this stream. Only sequential consistency forbids that outcome.
    ///
    /// The cost is one full barrier per body chunk — tens of nanoseconds against a 16 KiB frame, on the
    /// opt-in streaming path rather than the buffered hot path.
    func takeAll() -> Int {
        signalled.store(false, ordering: .sequentiallyConsistent)
        return bytes.exchange(0, ordering: .sequentiallyConsistent)
    }

    deinit {
        // No teardown beyond ARC.
    }
}
