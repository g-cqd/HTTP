//
//  TaskProviderSpyTests.swift
//  HTTPTestSupportTests
//
//  The tracking `TaskProvider`: spawns real tasks, settles them transitively, excludes `.observation`
//  loops, and times out deterministically under a `TestClock` when a `.work` task hangs.
//

import HTTPConcurrency
import Testing

@testable import HTTPTestSupport

@Suite("TaskProviderSpy")
struct TaskProviderSpyTests {

    @Test
    func `settles a batch of work tasks`() async throws {
        let spy = TaskProviderSpy()
        let probe = AsyncEventProbe<Int>()
        for i in 0..<5 { spy.task { probe.record(i) } }
        #expect(spy.spawnedCount == 5)
        try await spy.waitForAllTasks()
        #expect(spy.completedCount == 5)
        #expect(spy.liveCount == 0)
        #expect(probe.count == 5)
    }

    @Test
    func `settles tasks spawned by other tasks transitively`() async throws {
        let spy = TaskProviderSpy()
        let probe = AsyncEventProbe<Int>()
        spy.task {
            probe.record(1)
            spy.task { probe.record(2) }
        }
        try await spy.waitForAllTasks()
        #expect(spy.spawnedCount == 2)
        #expect(spy.completedCount == 2)
        #expect(probe.count == 2)
    }

    @Test
    func `observation tasks are excluded from settling`() async throws {
        let spy = TaskProviderSpy()
        let started = AsyncEventProbe<Int>()
        let handle = spy.task(role: .observation) {
            started.record(1)
            try? await Task.sleep(for: .seconds(86_400))
        }
        _ = try await started.wait(forAtLeast: 1)
        // No `.work` tasks tracked, so settling returns at once despite the live loop.
        try await spy.waitForAllTasks()
        #expect(spy.spawnedCount == 0)
        handle.cancel()
    }

    @Test
    func `a hung work task makes settling time out under a TestClock`() async throws {
        let clock = TestClock()
        let spy = TaskProviderSpy()
        let hanging = spy.task { try? await Task.sleep(for: .seconds(86_400)) }
        let advancer = Task {
            try await clock.waitForSleepers(atLeast: 1)
            clock.advance(by: .seconds(5))
        }
        await #expect(throws: AsyncEventProbeTimeoutError.self) {
            try await spy.waitForAllTasks(within: .seconds(5), clock: clock)
        }
        try await advancer.value
        hanging.cancel()
    }
}
