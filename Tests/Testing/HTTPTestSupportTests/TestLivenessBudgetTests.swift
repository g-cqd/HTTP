//
//  TestLivenessBudgetTests.swift
//  HTTPTestSupportTests
//
//  Audit FLAKE-1. These pin the two properties that make the budget a *liveness* guard rather than a
//  latency assertion — it only ever widens, and it is applied exactly once — because both failure modes
//  are silent. A scale below one reintroduces the flake it was written to remove; a scale applied twice
//  turns a 30 s guard into a 30-minute one on a CI runner asking for 60×, and a wedged test would then
//  hang the job rather than fail it.
//
//  The environment knob itself is not exercised here: it is read once into a `static let`, so a test
//  cannot set it after the fact without reaching into the process before any other test runs. The
//  parsing contract is instead pinned by construction — `scaled(_:)` is total in `scale`, and every
//  rejection path in the parse falls back to `1`.
//

import Testing

@testable import HTTPTestSupport

@Suite("HTTPTestSupport — TestLivenessBudget (audit FLAKE-1)")
struct TestLivenessBudgetTests {
    /// A run that shortened liveness budgets would fail *more* under load, which is backwards.
    @Test("the scale never shortens a budget")
    func scaleNeverShortens() {
        #expect(TestLivenessBudget.scale >= 1)
        #expect(TestLivenessBudget.scaled(.seconds(1)) >= .seconds(1))
    }

    /// The nominal budget is unscaled, so passing it through ``scaled(_:)`` cannot square the factor.
    ///
    /// This is the one that would rot quietly: making `nominal` pre-scaled reads as harmless, and on an
    /// unscaled host (the common case, factor 1) every assertion here still passes by coincidence.
    /// Asserting the *relationship* catches it on the hosts that matter.
    @Test("resolving the nominal budget applies the scale exactly once")
    func nominalIsUnscaled() {
        let resolvedOnce = TestLivenessBudget.scaled(TestLivenessBudget.nominal)
        let resolvedTwice = TestLivenessBudget.scaled(resolvedOnce)
        #expect(resolvedOnce == TestLivenessBudget.nominal * TestLivenessBudget.scale)
        // Equal only when the scale is 1; the point is that they are *not* the same expression.
        #expect((resolvedOnce == resolvedTwice) == (TestLivenessBudget.scale == 1))
    }

    /// Scaling is proportional, so a caller's relative ordering of budgets survives it.
    @Test("scaling preserves the ordering of budgets", arguments: [1, 2, 10, 30])
    func scalingIsMonotonic(seconds: Int) {
        let smaller = TestLivenessBudget.scaled(.seconds(seconds))
        let larger = TestLivenessBudget.scaled(.seconds(seconds + 1))
        #expect(smaller < larger)
    }

    /// The poll interval is deliberately *not* scaled — widening it only delays diagnosis.
    @Test("the poll interval is short and independent of the scale")
    func pollIntervalIsUnscaled() {
        #expect(TestLivenessBudget.pollInterval == .milliseconds(5))
        #expect(TestLivenessBudget.pollInterval < TestLivenessBudget.nominal)
    }
}
