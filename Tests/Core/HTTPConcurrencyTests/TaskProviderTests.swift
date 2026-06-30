//
//  TaskProviderTests.swift
//  HTTPConcurrencyTests
//
//  Phase 3.6 — the TaskProvider seam: the live provider actually runs the spawned operation, and a custom
//  provider can intercept each spawn (the basis for injecting an executor or counting tasks in a host).
//

import Testing

@testable import HTTPConcurrency

@Suite("Phase 3.6 — TaskProvider seam")
struct TaskProviderTests {
    @Test("the live provider runs the spawned operation")
    func liveRuns() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            LiveTaskProvider.spawn { continuation.resume() }
        }
        // Reaching here means the operation ran to completion on the spawned task.
    }

    @Test("a custom provider intercepts each spawn")
    func customIntercepts() {
        let counter = Counter()
        let operation: @Sendable () async -> Void = { await Task.yield() }
        let provider: TaskProvider = { _ in counter.increment() }
        provider(operation)
        provider(operation)
        #expect(counter.value == 2)
    }

    /// A spawn counter (the custom provider above calls it synchronously, so a plain class suffices).
    private final class Counter: @unchecked Sendable {
        private(set) var value = 0

        func increment() {
            value += 1
        }

        deinit {
            // No teardown beyond ARC.
        }
    }
}
