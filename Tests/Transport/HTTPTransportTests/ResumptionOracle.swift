//
//  ResumptionOracle.swift
//  HTTPTransportTests
//
//  A BOUNDED oracle for "the owning task never resumed" — the failure mode the direction-ownership
//  contract exists to prevent (CWE-833, deadlock by lost wakeup), and the one an ordinary test cannot
//  observe without becoming it.
//
//  The problem this solves, stated exactly. Reinstating the unconditional single-slot overwrite in
//  ``OnceResumer/claim(_:)`` drops the incumbent's continuation. The task holding it is then parked
//  forever: nothing will resume it, and — this is the part that defeats every in-process
//  `withTimeout`-style race — nothing can cancel it either. `UnsafeContinuation` has no cancellation
//  path, so `Task.cancel()` on the parked task returns immediately and changes nothing; the task stays
//  suspended for the life of the process. A test that then `await`s that task's `.value` inherits the
//  hang, and the only thing that ends it is the runner's own `.timeLimit` — a whole minute of a job's
//  budget spent to produce "test exceeded time limit", which names neither the direction nor the
//  operation nor the mechanism.
//
//  So the oracle does not try to RECLAIM the parked task, because that is impossible. It only refuses
//  to WAIT ON it. The observation runs in a detached task that reports its outcome through an
//  ``AsyncEventProbe``; the test awaits the *probe*, never the task, against a deadline fixed once at
//  construction. A stalled role therefore costs a bounded, named failure instead of a hang, and every
//  role in one scenario shares ONE deadline — N stalled operations still cost one budget, not N.
//
//  The residual cost is a leak: the parked task and its continuation are abandoned, and stay abandoned
//  until the process exits. That is the correct trade. It happens only on a run that is already failing
//  (a green run resumes every role and leaks nothing), and the alternative is not "no leak" — it is the
//  same leak plus a hang.
//
//  Why not a subprocess. It was the first shape tried and it does not survive contact with the test
//  products this package builds. There is no standalone runner to re-exec: SwiftPM emits
//  `.build/out/Products/Debug/HTTPTransportTests.xctest`, a Darwin bundle invoked through `xctest`,
//  whose selector vocabulary is XCTest's and not Swift Testing's — while on Linux the same target is a
//  plain executable that does take `--filter`. Re-execing therefore means two different mechanisms on
//  the two platforms this suite is required to run on identically, both of them pinned to a
//  toolchain-internal invocation contract. The remaining subprocess route, shelling out to
//  `swift test --filter`, nests a build inside a test. Neither is worth it: the property that actually
//  matters is that the OBSERVER is never parked on the dropped continuation, and that is a property of
//  where the wait lives, not of which process it lives in.
//
//  The budget is ``TestLivenessBudget``'s, deliberately not a fresh one — audit FLAKE-1 was ad-hoc
//  deadlines, and a liveness guard's budget must be generous, scalable from the environment, and
//  stated in exactly one place.
//

import HTTPTestSupport
import Testing

/// A single bounded deadline for one scenario's resumptions, and the diagnostic when one lapses.
///
/// Construct one per scenario, then observe each role through ``resumption(of:_:)``. The deadline is
/// fixed at construction and SHARED across roles, so a scenario with several stalled operations still
/// costs one budget rather than one per role.
struct ResumptionOracle: Sendable {
    /// Which half of the connection's octet stream the observed operation owns.
    ///
    /// Named in the failure text because "a task never resumed" is not actionable and "the inbound
    /// direction's receive never resumed" is — the two directions have separate owners, and which one
    /// stalled is the first thing a reader needs (RFC 9293 §3.1: one sequence space per direction).
    enum Direction: String, Sendable {
        case inbound
        case outbound
    }

    private let direction: Direction
    private let operation: String
    private let deadline: ContinuousClock.Instant

    /// Opens a bounded observation window for `operation` on `direction`.
    ///
    /// `budget` is scaled by ``TestLivenessBudget/scale`` exactly once, here, so a caller cannot state
    /// a budget the environment knob then fails to widen.
    init(
        direction: Direction,
        operation: String,
        budget: Duration = TestLivenessBudget.nominal
    ) {
        self.direction = direction
        self.operation = operation
        self.deadline = ContinuousClock.now.advanced(by: TestLivenessBudget.scaled(budget))
    }

    /// Runs `work` detached and returns how it finished, or `nil` when the shared deadline lapsed with
    /// it still parked — recording an ``Issue`` that names the direction, the operation and the role.
    ///
    /// `work` is where the `await` on a possibly-parked task belongs. It MUST NOT be inlined into the
    /// test body: awaiting the task directly is precisely the hang this exists to bound, and no trait
    /// or task-group timeout can undo it, because a task parked on a dropped `UnsafeContinuation` is
    /// unreachable by cancellation.
    ///
    /// The detached task is deliberately unstructured: a structured child would make the enclosing
    /// scope wait for it on the way out, reintroducing the hang at the end of the test instead of the
    /// middle. When the deadline lapses that task is abandoned, along with the continuation it holds.
    /// `sourceLocation` defaults to the HARVEST site rather than the oracle's construction site: a
    /// scenario observes several roles against one oracle, and "which await would have hung" is the
    /// line a reader needs.
    func resumption<Value: Sendable>(
        of role: String,
        sourceLocation: SourceLocation = #_sourceLocation,
        _ work: @escaping @Sendable () async throws -> Value
    ) async -> Result<Value, any Error>? {
        let landed = AsyncEventProbe<Result<Value, any Error>>()
        Task.detached {
            do {
                landed.record(.success(try await work()))
            }
            catch {
                landed.record(.failure(error))
            }
        }
        // The clock-injectable overload, so the already-scaled remainder is not scaled a second time.
        // A lapsed deadline yields `.zero`, which the probe still honors as one final re-check.
        let remaining = max(.zero, ContinuousClock.now.duration(to: deadline))
        do {
            let landings = try await landed.wait(
                forAtLeast: 1,
                within: remaining,
                clock: ContinuousClock()
            )
            return landings.first
        }
        catch {
            Issue.record(
                """
                \(role) never resumed: the \(direction.rawValue) direction's \(operation) is parked \
                on a continuation nothing will resume, and nothing can cancel it (CWE-833, deadlock \
                by lost wakeup). The single-slot resumer displaced a pending continuation instead of \
                refusing the intruder.
                """,
                sourceLocation: sourceLocation
            )
            return nil
        }
    }
}
