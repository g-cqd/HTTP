//
//  ManualClock.swift
//  HTTPServerTests
//
//  A deterministic Clock for timing assertions: `now` advances only when the test (or the handler
//  under test) advances it, so a measured duration is exact and reproducible — never wall-clock flake.
//

import Synchronization

/// A deterministic ``Clock`` whose `now` advances only when the test (or handler) says so.
final class ManualClock: Clock {
    /// A point in the clock's monotonic timeline, counted in nanoseconds from zero.
    struct Instant: InstantProtocol {
        let nanos: Int64

        func advanced(by duration: Duration) -> Self {
            let (seconds, attoseconds) = duration.components
            return Self(nanos: nanos + seconds * 1_000_000_000 + attoseconds / 1_000_000_000)
        }

        func duration(to other: Self) -> Duration {
            .nanoseconds(other.nanos - nanos)
        }

        static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.nanos < rhs.nanos
        }
    }

    private let state = Mutex<Instant>(Instant(nanos: 0))

    var now: Instant { state.withLock(\.self) }
    var minimumResolution: Duration { .nanoseconds(1) }

    /// Moves the clock forward by `duration` (simulating elapsed time around an awaited call).
    func advance(by duration: Duration) {
        state.withLock { $0 = $0.advanced(by: duration) }
    }

    func sleep(until _: Instant, tolerance _: Duration?) async throws {
        try Task.checkCancellation()  // never slept on here; honor cancellation regardless
    }

    deinit {
        // No teardown beyond ARC.
    }
}
