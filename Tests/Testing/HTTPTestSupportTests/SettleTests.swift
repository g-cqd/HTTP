//
//  SettleTests.swift
//  HTTPTestSupportTests
//
//  Audit FLAKE-1. The property that matters is the one four of the seventeen hand-rolled copies got
//  wrong: an exhausted budget must be a *failure*, not a silent return. Those copies were
//
//      for _ in 0 ..< 200 where !condition() { try await Task.sleep(for: .milliseconds(10)) }
//
//  with nothing after the brace, so a test whose wait expired went on to assert against a state that
//  never arrived — and where the assertion reads `#expect(count == 0)` on something not yet
//  populated, it **passed**. That is worse than a missing test, because it reports as coverage.
//
//  What is NOT asserted here, and why: the exhaustion path itself. Its failure mode *is* a recorded
//  test failure, so provoking it would fail this suite, and there is no supported way to catch an
//  `#expect` from inside the test that caused it. The guard against regression is instead structural —
//  the budget is derived from ``TestLivenessBudget`` rather than written down, and there is exactly one
//  copy of the loop to inspect. Saying so beats a test that appears to cover it and does not.
//

internal import Synchronization
import Testing

@testable import HTTPTestSupport

@Suite("HTTPTestSupport — settle (audit FLAKE-1)")
struct SettleTests {
    /// No sleep when the condition already holds — asserted by evaluation count, not by elapsed time.
    ///
    /// A wall-clock bound here would be the very thing this whole finding was about: a latency
    /// assertion dressed as a correctness one, failing on a loaded host for no reason.
    @Test("a condition already true is evaluated once and returns")
    func returnsWithoutPolling() async throws {
        let condition = CountingCondition(trueAfter: 0)
        try await settle { condition.evaluate() }
        #expect(condition.evaluations == 1)
    }

    @Test("a condition that becomes true mid-poll is observed", arguments: [1, 3, 7])
    func observesALateCondition(afterEvaluations: Int) async throws {
        let condition = CountingCondition(trueAfter: afterEvaluations)
        try await settle { condition.evaluate() }
        #expect(condition.evaluations == afterEvaluations + 1)
    }

    /// The budget is derived, so raising ``TestLivenessBudget/nominal`` cannot leave the loop counting
    /// to a number chosen for the old one — the drift that gave seventeen copies three budgets.
    @Test("the poll count covers the whole resolved budget")
    func pollCountCoversTheBudget() {
        let covered = TestLivenessBudget.pollInterval * TestLivenessBudget.pollCount
        #expect(covered >= TestLivenessBudget.scaled(TestLivenessBudget.nominal))
        #expect(TestLivenessBudget.pollCount >= 1)
    }

    /// `advance` must not advance a clock that is already where the test wants it.
    ///
    /// Over-advancing an injected clock is not harmless: it can fire *other* deadlines and change what
    /// the test observes. Checking before advancing is what makes this safe to use in place of the
    /// copies that capped their advance count by hand — those caps existed for exactly this reason.
    @Test("advance checks the condition before touching the clock")
    func advanceChecksBeforeAdvancing() async throws {
        let clock = TestClock()
        let start = clock.now
        try await advance(clock, by: .seconds(31)) { true }
        #expect(clock.now == start)
    }

    @Test("advance moves the clock only until the condition holds")
    func advanceMovesTheClock() async throws {
        let clock = TestClock()
        let start = clock.now
        try await advance(clock, by: .seconds(1)) { clock.now.offset - start.offset >= .seconds(3) }
        // Stops on arrival rather than overshooting: an extra advance could fire another deadline.
        #expect(clock.now.offset - start.offset == .seconds(3))
    }

    /// A condition that turns true after a set number of evaluations, counting every call.
    private final class CountingCondition: Sendable {
        private let state: Mutex<Int>
        private let threshold: Int

        init(trueAfter threshold: Int) {
            self.threshold = threshold
            state = Mutex(0)
        }

        var evaluations: Int { state.withLock(\.self) }

        func evaluate() -> Bool {
            state.withLock {
                $0 += 1
                return $0 > threshold
            }
        }

        deinit {
            // No teardown beyond ARC.
        }
    }
}
