//
//  TestMonotonicClock.swift
//  HTTPServerTests
//
//  A manually advanced monotonic clock for the seams that take a ``MonotonicNowProvider`` but are not
//  driven by the shared ``TestClock`` — currently ``InMemorySessionStore``'s sliding TTL, which has to
//  be advanced independently of the session token's wall-clock expiry so the two bounds can be
//  distinguished (audit R5-SEC2).
//

import HTTPConcurrency

/// A monotonic clock a test advances by hand.
final class TestMonotonicClock: @unchecked Sendable {
    private var nanoseconds: MonotonicNanoseconds = 0

    deinit {
        // No teardown beyond ARC; the counter releases with the instance.
    }

    /// A ``MonotonicNowProvider`` reading this clock.
    var now: MonotonicNowProvider { { [self] in nanoseconds } }

    /// Moves the clock forward by `duration`.
    func advance(by duration: Duration) {
        nanoseconds += duration.monotonicNanoseconds
    }
}
