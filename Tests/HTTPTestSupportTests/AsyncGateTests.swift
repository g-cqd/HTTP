//
//  AsyncGateTests.swift
//  HTTPTestSupportTests
//
//  The one-permit async gate: holders suspend until `open()`, a permit is banked when no holder
//  waits, and `waitForWaiters` sequences the interleaving without a `Task.yield()` spin.
//

import Testing

@testable import HTTPTestSupport

@Suite("AsyncGate")
struct AsyncGateTests {
    @Test
    func `an initially-open gate lets the first waiter through without suspending`() async throws {
        let gate = AsyncGate(initiallyOpen: true)
        try await gate.waitUntilOpen()  // consumes the banked permit
        #expect(gate.waiterCount == 0)
    }

    @Test
    func `open resumes a suspended holder`() async throws {
        let gate = AsyncGate()
        let passed = AsyncEventProbe<Int>()
        let holder = Task {
            try await gate.waitUntilOpen()
            passed.record(1)
        }
        try await gate.waitForWaiters(atLeast: 1)  // holder is parked — no yield spin
        #expect(passed.events.isEmpty)
        gate.open()
        try await holder.value
        #expect(passed.events == [1])
    }

    @Test
    func `open with no waiter banks a permit for the next waiter`() async throws {
        let gate = AsyncGate()
        gate.open()  // no waiter yet → banked
        try await gate.waitUntilOpen()  // consumes the banked permit, returns at once
        #expect(gate.waiterCount == 0)
    }

    @Test
    func `a cancelled waitUntilOpen throws CancellationError and unregisters`() async throws {
        let gate = AsyncGate()
        let holder = Task { try await gate.waitUntilOpen() }
        try await gate.waitForWaiters(atLeast: 1)
        holder.cancel()
        await #expect(throws: CancellationError.self) { try await holder.value }
    }
}
