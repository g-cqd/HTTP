//
//  TestClockTests.swift
//  HTTPTestSupportTests
//
//  The deterministic manual clock: time advances only on `advance`, sleepers wake in deadline order,
//  and `waitForSleepers` sequences a test without a `Task.yield()` spin.
//

import Testing

@testable import HTTPTestSupport

@Suite("TestClock")
struct TestClockTests {
    @Test
    func `now advances only when told`() {
        let clock = TestClock()
        #expect(clock.now == TestClock.Instant())
        clock.advance(by: .seconds(5))
        #expect(clock.now == TestClock.Instant(offset: .seconds(5)))
    }

    @Test
    func `a sleeper wakes exactly when time is advanced past its deadline`() async throws {
        let clock = TestClock()
        let woke = AsyncEventProbe<Int>()
        let sleeper = Task {
            try await clock.sleep(until: clock.now.advanced(by: .seconds(10)))
            woke.record(1)
        }
        // waitForSleepers replaces `while clock.sleeperCount == 0 { await Task.yield() }`.
        try await clock.waitForSleepers(atLeast: 1)
        #expect(clock.sleeperCount == 1)
        #expect(woke.count == 0)

        clock.advance(by: .seconds(9))  // not yet past the deadline
        #expect(woke.count == 0)
        clock.advance(by: .seconds(1))  // now at the deadline
        try await sleeper.value
        #expect(woke.events == [1])
        #expect(clock.sleeperCount == 0)
    }

    @Test
    func `a deadline already in the past returns without parking`() async throws {
        let clock = TestClock()
        clock.advance(by: .seconds(100))
        try await clock.sleep(until: clock.now.advanced(by: .seconds(-1)))
        #expect(clock.sleeperCount == 0)
    }

    @Test
    func `advance(to:) wakes a sleeper and is a no-op once already past it`() async throws {
        let clock = TestClock()
        let woke = AsyncEventProbe<Int>()
        let sleeper = Task {
            try await clock.sleep(until: TestClock.Instant(offset: .seconds(10)))
            woke.record(1)
        }
        try await clock.waitForSleepers(atLeast: 1)
        clock.advance(to: TestClock.Instant(offset: .seconds(10)))
        try await sleeper.value
        #expect(woke.events == [1])

        let before = clock.now
        clock.advance(to: TestClock.Instant(offset: .seconds(5)))  // already past → no-op
        #expect(clock.now == before)
    }

    @Test
    func `runToLastSleeper drains every parked sleeper`() async throws {
        let clock = TestClock()
        let woke = AsyncEventProbe<Int>()
        for seconds in [5, 20, 100] {
            Task {
                try? await clock.sleep(until: TestClock.Instant(offset: .seconds(seconds)))
                woke.record(seconds)
            }
        }
        try await clock.waitForSleepers(atLeast: 3)
        clock.runToLastSleeper()
        _ = try await woke.wait(forAtLeast: 3)
        #expect(Set(woke.events) == [5, 20, 100])
        #expect(clock.sleeperCount == 0)
    }

    @Test
    func `a cancelled sleeper throws CancellationError and unregisters`() async throws {
        let clock = TestClock()
        let sleeper = Task {
            try await clock.sleep(until: TestClock.Instant(offset: .seconds(1_000)))
        }
        try await clock.waitForSleepers(atLeast: 1)
        sleeper.cancel()
        await #expect(throws: CancellationError.self) { try await sleeper.value }
    }

    @Test
    func `nowProvider reports advanced time as monotonic nanoseconds`() {
        let clock = TestClock()
        let now = clock.nowProvider
        #expect(now() == 0)
        clock.advance(by: .seconds(2))
        #expect(now() == 2_000_000_000)
        clock.advance(by: .milliseconds(500))
        #expect(now() == 2_500_000_000)
    }
}
