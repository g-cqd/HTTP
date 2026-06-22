//
//  AsyncEventProbeTests.swift
//  HTTPTestSupportTests
//
//  The suspend-until-count event boundary: `wait` returns once enough events land, times out
//  deterministically under a `TestClock` (zero real time), and honors cancellation.
//

import Testing

@testable import HTTPTestSupport

@Suite("AsyncEventProbe")
struct AsyncEventProbeTests {

    @Test
    func `wait returns the recorded events once the threshold is met`() async throws {
        let probe = AsyncEventProbe<Int>()
        let recorder = Task {
            for i in 1...3 { probe.record(i) }
        }
        let events = try await probe.wait(forAtLeast: 3)
        #expect(events.count >= 3)
        await recorder.value
        #expect(probe.events == [1, 2, 3])
    }

    @Test
    func `a non-positive threshold returns immediately with the current events`() async throws {
        let probe = AsyncEventProbe<Int>()
        probe.record(7)
        let events = try await probe.wait(forAtLeast: 0)
        #expect(events == [7])
    }

    @Test
    func `wait times out deterministically under a TestClock with zero real time`() async throws {
        let clock = TestClock()
        let probe = AsyncEventProbe<Int>()
        // Advance only once the timeout sleeper has registered — no Task.yield spin.
        let advancer = Task {
            try await clock.waitForSleepers(atLeast: 1)
            clock.advance(by: .seconds(5))
        }
        await #expect(throws: AsyncEventProbeTimeoutError.self) {
            try await probe.wait(forAtLeast: 1, within: .seconds(5), clock: clock)
        }
        try await advancer.value
    }

    @Test
    func `a cancelled wait resumes with CancellationError`() async throws {
        let clock = TestClock()
        let probe = AsyncEventProbe<Int>()
        let waiter = Task {
            try await probe.wait(forAtLeast: 5, within: .seconds(60), clock: clock)
        }
        // The wait's timeout branch parks on the clock; once it has, cancel.
        try await clock.waitForSleepers(atLeast: 1)
        waiter.cancel()
        await #expect(throws: CancellationError.self) { _ = try await waiter.value }
    }
}
