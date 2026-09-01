//
//  Settle.swift
//  HTTPTestSupport
//
//  One polling wait for tests that observe a condition reached by another task.
//
//  Audit FLAKE-1, third part. `Tests/Server/HTTPServerTests/` carried **seventeen** hand-rolled copies
//  of this loop, and they had drifted apart in all three ways a copied primitive can:
//
//  • **Budget.** `0 ..< 200` at 5 ms in some files, at 10 ms in others, `0 ..< 300` in one — 1 s, 2 s
//    and 3 s of real time from what reads as the same loop. All calibrated on an idle machine, which
//    is what the rest of FLAKE-1 was about.
//  • **Assertion.** Four copies simply *fell out* of the loop when the budget ran out. A test whose
//    settle expires then proceeds to assert against a state that never arrived, and where the
//    assertion is a `#expect(x == 0)` on something not yet populated, it **passes vacuously**. The
//    REG-6 work fixed this in some copies; there was no mechanism to fix it in all of them.
//  • **Shape.** Sync condition, async condition, `advance(_:by:times:)`, `advance(_:by:until:)`,
//    `settle(rounds:)` — five signatures for two ideas.
//
//  So the loop lives here once, it takes its budget from ``TestLivenessBudget``, and it always
//  asserts. The `sourceLocation` default carries the *caller's* line, so an exhausted budget points at
//  the test that waited rather than at this file.
//

public import Testing

/// Polls `condition` until it holds, failing at the caller's line if the budget runs out.
///
/// Accepts a synchronous condition too — Swift admits a non-`async` function wherever an `async` one
/// is expected — so this single entry point replaces both spellings.
///
/// The budget is a liveness guard (see ``TestLivenessBudget``): reaching it means the condition never
/// became true, not that it took too long. It is therefore an assertion failure, never a silent return.
public func settle(
    until condition: @Sendable () async -> Bool,
    _ comment: Comment? = nil,
    sourceLocation: SourceLocation = #_sourceLocation
) async throws {
    let interval = TestLivenessBudget.pollInterval
    for _ in 0 ..< TestLivenessBudget.pollCount {
        if await condition() {
            return
        }
        try await Task.sleep(for: interval)
    }
    let satisfied = await condition()
    #expect(
        satisfied,
        comment ?? "settle budget exhausted with the condition still false",
        sourceLocation: sourceLocation
    )
}

/// Advances `clock` by `step` until `condition` holds, failing at the caller's line if it never does.
///
/// The sleep between advances is not a budget for the condition — it is the scheduling opportunity the
/// tasks under test need in order to observe the advanced clock and park on their next deadline. The
/// *bound* is still ``TestLivenessBudget``, so a test driving an injected clock is no more fragile on a
/// loaded host than one driving real time.
public func advance(
    _ clock: TestClock,
    by step: Duration,
    until condition: @Sendable () async -> Bool,
    _ comment: Comment? = nil,
    sourceLocation: SourceLocation = #_sourceLocation
) async throws {
    let interval = TestLivenessBudget.pollInterval
    for _ in 0 ..< TestLivenessBudget.pollCount {
        if await condition() {
            return
        }
        clock.advance(by: step)
        try await Task.sleep(for: interval)
    }
    let satisfied = await condition()
    #expect(
        satisfied,
        comment ?? "advance budget exhausted with the condition still false",
        sourceLocation: sourceLocation
    )
}
