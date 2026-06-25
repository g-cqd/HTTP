//
//  TestClock.swift
//  HTTPTestSupport
//
//  A deterministic `Clock` whose time advances only when a test calls `advance(by:)`. Sleepers
//  suspend until time is manually advanced past their deadline, so time-dependent code (the server's
//  Slowloris/idle timeouts, the HTTP/2 Rapid Reset window) is pinned with *zero* real-time waiting.
//

public import HTTPConcurrency
internal import Synchronization

/// A deterministic `Clock` whose time advances only when a test calls ``advance(by:)``.
///
/// Two things beyond a plain manual clock: ``waitForSleepers(atLeast:)`` *suspends* until a sleeper
/// registers (so a test never spins `while sleeperCount == 0 { Task.yield() }`), and ``nowProvider``
/// bridges to the ``MonotonicNowProvider`` seam, so one `TestClock` drives both the server's
/// `clock.sleep` and the HTTP/2 engine's monotonic `now`. The parked sleepers live in a shared
/// ``ContinuationRegistry`` (a deadline-ordered heap), so waking the due ones is a few pops.
public final class TestClock: Clock, Sendable {
    /// An instant measured as an elapsed `Duration` from the clock's origin.
    public struct Instant: InstantProtocol, Sendable {
        /// Elapsed `Duration` since the clock's origin.
        public var offset: Duration

        /// Creates an instant `offset` past the origin.
        public init(offset: Duration = .zero) { self.offset = offset }

        /// The instant `duration` after this one.
        public func advanced(by duration: Duration) -> Self {
            Self(offset: offset + duration)
        }

        /// The signed `Duration` from this instant to `other`.
        public func duration(to other: Self) -> Duration {
            other.offset - offset
        }

        /// Orders two instants by their elapsed offset.
        public static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.offset < rhs.offset
        }
    }

    private struct State {
        var now: Instant
        var sleepers = ContinuationRegistry<Instant, Void>()
        /// Waiters parked in ``waitForSleepers(atLeast:)``, keyed by the sleeper-count threshold they
        /// await; woken when a new sleeper pushes the live count up to their key.
        var countWaiters = ContinuationRegistry<Int, Void>()
    }

    private let state: Mutex<State>

    /// Creates a clock whose origin is `now`.
    public init(now: Instant = Instant()) {
        state = Mutex(State(now: now))
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// The current instant — advances only when a test calls ``advance(by:)``.
    public var now: Instant { state.withLock(\.now) }

    /// The clock's minimum resolution (zero — it is purely logical).
    public var minimumResolution: Duration { .zero }

    /// How many tasks are currently parked in `sleep`.
    ///
    /// Lets a test assert state without advancing.
    public var sleeperCount: Int { state.withLock(\.sleepers.count) }

    /// This clock's elapsed time as monotonic nanoseconds — the unit the ``MonotonicNowProvider``
    /// seam measures against.
    public var monotonicNanoseconds: MonotonicNanoseconds { now.offset.monotonicNanoseconds }

    /// A ``MonotonicNowProvider`` backed by this clock, so injecting it into the HTTP/2 engine makes
    /// the Rapid Reset window advance exactly when the test advances the clock.
    public var nowProvider: MonotonicNowProvider { { [self] in monotonicNanoseconds } }

    /// Suspends until time is advanced to or past `deadline`, honoring cancellation.
    public func sleep(until deadline: Instant, tolerance _: Duration? = nil) async throws {
        try Task.checkCancellation()
        let id = state.withLock { $0.sleepers.makeID() }
        enum Action { case resumeNow, cancelled, suspended }
        try await withTaskCancellationHandler {
            // Keep the closure parameter clauses on the brace line for swiftlint
            // (closure_parameter_position); the collapsed signatures exceed swift-format's lineLength,
            // so this one statement is exempted from swift-format below.
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                let resumals = state.withLock {
                    s -> (Action, [(UnsafeContinuation<Void, any Error>, Void)]) in
                    if Task.isCancelled {
                        return (.cancelled, [])
                    }
                    if deadline <= s.now {
                        return (.resumeNow, [])
                    }
                    s.sleepers.park(id: id, key: deadline, continuation)
                    // A new sleeper may satisfy a `waitForSleepers` threshold — wake those waiters.
                    return (.suspended, s.countWaiters.wake(upTo: s.sleepers.count, with: ()))
                }
                for (waiter, _) in resumals.1 { waiter.resume() }
                switch resumals.0 {
                    case .resumeNow:
                        continuation.resume()
                    case .cancelled:
                        continuation.resume(throwing: CancellationError())
                    case .suspended:
                        break
                }
            }
        } onCancel: {
            state.withLock { $0.sleepers.remove(id: id) }?.resume(throwing: CancellationError())
        }
    }

    /// Suspends until at least `count` tasks are parked in `sleep`, then returns.
    ///
    /// The deterministic replacement for `while sleeperCount < count { await Task.yield() }`. Honors
    /// cancellation.
    public func waitForSleepers(atLeast count: Int) async throws {
        if count <= 0 {
            return
        }
        let id = state.withLock { $0.countWaiters.makeID() }
        enum Action { case ready, cancelled, suspended }
        try await withTaskCancellationHandler {
            // Keep the closure parameter clause on the brace line for swiftlint
            // (closure_parameter_position); the collapsed signature exceeds swift-format's lineLength,
            // so this one statement is exempted from swift-format below.
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                let action = state.withLock { s -> Action in
                    if Task.isCancelled {
                        return .cancelled
                    }
                    if s.sleepers.count >= count {
                        return .ready
                    }
                    s.countWaiters.park(id: id, key: count, continuation)
                    return .suspended
                }
                switch action {
                    case .ready:
                        continuation.resume()
                    case .cancelled:
                        continuation.resume(throwing: CancellationError())
                    case .suspended:
                        break
                }
            }
        } onCancel: {
            state.withLock { $0.countWaiters.remove(id: id) }?.resume(throwing: CancellationError())
        }
    }

    /// Advances time by `duration`, waking every sleeper whose deadline is now due (in deadline
    /// order).
    ///
    /// Continuations resume *outside* the lock.
    public func advance(by duration: Duration) {
        let woken = state.withLock { s -> [(UnsafeContinuation<Void, any Error>, Void)] in
            s.now = s.now.advanced(by: duration)
            return s.sleepers.wake(upTo: s.now, with: ())
        }
        for (continuation, _) in woken { continuation.resume() }
    }

    /// Advances to a specific instant (no-op if already past it).
    public func advance(to instant: Instant) {
        let delta = state.withLock { $0.now.duration(to: instant) }
        if delta > .zero { advance(by: delta) }
    }

    /// Wakes every parked sleeper by advancing to the furthest pending deadline — the "drain
    /// everything" step at the end of a deterministic time test.
    public func runToLastSleeper() {
        let furthest = state.withLock(\.sleepers.maxKey)
        if let furthest { advance(to: furthest) }
    }
}
