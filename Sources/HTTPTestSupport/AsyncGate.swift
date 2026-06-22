//
//  AsyncGate.swift
//  HTTPTestSupport
//
//  A one-permit gate that **suspends a Task** instead of blocking an OS thread: a holder `await`s
//  `waitUntilOpen()` and the cooperative thread is released back to the pool; `open()` resumes the
//  longest-waiting holder, or banks a permit if none is waiting. The `Task`-based counterpart for code
//  on async/await (`ThreadGate` remains the tool for the pthread / dispatch-queue engine paths).
//

internal import Synchronization

/// A one-permit gate that suspends a `Task` until opened.
///
/// Built on the shared ``ContinuationRegistry`` — fully `Sendable`, no `Dispatch`. Continuations
/// resume *outside* the lock, and a cancelled `waitUntilOpen()` throws `CancellationError` and
/// unregisters. ``waitForWaiters(atLeast:)`` lets a test suspend until a holder has parked, so the
/// interleaving is sequenced without a `Task.yield()` spin.
public final class AsyncGate: Sendable {
    private struct State {
        /// Banked permits from `open()` calls that arrived with no waiter parked.
        var permits: Int
        /// Suspended holders, all parked at key 0 so `wakeOne()` releases them FIFO (by id).
        var waiters = ContinuationRegistry<Int, Void>()
        /// Waiters parked in ``waitForWaiters(atLeast:)``, keyed by the holder-count threshold.
        var countWaiters = ContinuationRegistry<Int, Void>()
    }

    private let state: Mutex<State>

    /// A closed gate (the usual case): holders suspend until `open()`. `initiallyOpen` banks one
    /// permit, so the first `waitUntilOpen()` returns without suspending.
    public init(initiallyOpen: Bool = false) {
        state = Mutex(State(permits: initiallyOpen ? 1 : 0))
    }

    /// Tasks currently suspended on the gate — the async analogue of ``TestClock/sleeperCount``.
    public var waiterCount: Int { state.withLock { $0.waiters.count } }

    /// Suspends until the gate is opened, or consumes a banked permit and proceeds at once.
    ///
    /// Honors cancellation: a cancelled wait throws `CancellationError` and unregisters.
    public func waitUntilOpen() async throws {
        try Task.checkCancellation()
        let id = state.withLock { $0.waiters.makeID() }
        enum Action { case proceed, cancelled, suspended }
        try await withTaskCancellationHandler {
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                let resumals = state.withLock {
                    s -> (Action, [(UnsafeContinuation<Void, any Error>, Void)]) in
                    if Task.isCancelled { return (.cancelled, []) }
                    if s.permits > 0 {
                        s.permits -= 1
                        return (.proceed, [])
                    }
                    s.waiters.park(id: id, key: 0, continuation)
                    // A new holder may satisfy a `waitForWaiters` threshold — wake those waiters.
                    return (.suspended, s.countWaiters.wake(upTo: s.waiters.count, with: ()))
                }
                for (waiter, _) in resumals.1 { waiter.resume() }
                switch resumals.0 {
                case .proceed: continuation.resume()
                case .cancelled: continuation.resume(throwing: CancellationError())
                case .suspended: break
                }
            }
        } onCancel: {
            state.withLock { $0.waiters.remove(id: id) }?.resume(throwing: CancellationError())
        }
    }

    /// Suspends until at least `count` holders are parked on the gate, then returns — the
    /// deterministic replacement for `while waiterCount < count { await Task.yield() }`.
    public func waitForWaiters(atLeast count: Int) async throws {
        if count <= 0 { return }
        let id = state.withLock { $0.countWaiters.makeID() }
        enum Action { case ready, cancelled, suspended }
        try await withTaskCancellationHandler {
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                let action = state.withLock { s -> Action in
                    if Task.isCancelled { return .cancelled }
                    if s.waiters.count >= count { return .ready }
                    s.countWaiters.park(id: id, key: count, continuation)
                    return .suspended
                }
                switch action {
                case .ready: continuation.resume()
                case .cancelled: continuation.resume(throwing: CancellationError())
                case .suspended: break
                }
            }
        } onCancel: {
            state.withLock { $0.countWaiters.remove(id: id) }?.resume(throwing: CancellationError())
        }
    }

    /// Opens the gate for one holder: resumes the longest-waiting suspended Task, or banks a permit if
    /// none is waiting.
    ///
    /// The continuation resumes outside the lock.
    public func open() {
        let woken = state.withLock { s -> UnsafeContinuation<Void, any Error>? in
            if let continuation = s.waiters.wakeOne() { return continuation }
            s.permits += 1
            return nil
        }
        woken?.resume()
    }
}
