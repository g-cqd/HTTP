//
//  ThreadGate.swift
//  HTTPTestSupport
//
//  A deterministic gate for forcing a specific interleaving without sleeps or timing. A holder
//  occupies a serial resource (e.g. a dispatch-queue accept loop) and blocks on the gate; concurrent
//  work then provably piles up behind it; opening the gate releases the holder. The deterministic
//  concurrency tool for the *pthread / dispatch-queue* transport backbones (which must occupy a real
//  thread) — `AsyncGate` is the counterpart for code already on async/await.
//

internal import Dispatch

/// A deterministic gate that blocks a real thread/queue until opened.
///
/// `DispatchSemaphore` is a thread-safe reference type, so this wrapper is `Sendable` and can cross
/// into a detached holder task or a raw worker thread.
public struct ThreadGate: Sendable {
    private let gate: DispatchSemaphore

    /// A closed gate (the usual case): waiters block until `open()`. `initiallyOpen` pre-arms one
    /// permit.
    ///
    /// The backing semaphore is always created at value 0 and *signalled* up when `initiallyOpen` —
    /// never created at value 1. libdispatch traps ("semaphore object deallocated while in use")
    /// whenever a `DispatchSemaphore` is destroyed with a value below the one it was *created* with,
    /// so a `value: 1` gate whose single permit is consumed and then dropped would crash on
    /// deallocation. Creating at 0 and signalling keeps every balanced-or-over-signalled use safe.
    public init(initiallyOpen: Bool = false) {
        gate = DispatchSemaphore(value: 0)
        if initiallyOpen { gate.signal() }
    }

    /// Blocks the current thread/queue until the gate opens.
    ///
    /// Called *inside* the holder once it has occupied the serial resource, so everything enqueued
    /// afterward is guaranteed to wait behind it.
    public func waitUntilOpen() { gate.wait() }

    /// Releases exactly one waiter.
    ///
    /// Call after the piled-up work has been enqueued.
    public func open() { gate.signal() }
}

/// Runs the full gated-batch pattern: spawn `hold` (which must occupy the serial resource and call
/// `gate.waitUntilOpen()` inside it), run `body` to enqueue the work that should pile up behind the
/// holder, then open the gate and join the holder.
///
/// Deterministic — the batch is guaranteed assembled before the gate opens, with no timing
/// assumptions.
public func withThreadGatedBatch(
    hold: @escaping @Sendable (_ gate: ThreadGate) -> Void,
    _ body: (_ openGate: @Sendable () -> Void) async throws -> Void
) async rethrows {
    let gate = ThreadGate()
    let holder = Task.detached { hold(gate) }
    try await body { gate.open() }
    _ = await holder.value
}
