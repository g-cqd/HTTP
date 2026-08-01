//
//  TestLivenessBudget.swift
//  HTTPTestSupport
//
//  One source for every real-time budget an async test races against.
//
//  Audit FLAKE-1. The recurring "flaky" failures across `HTTPTransportTests`, `ResponderGenerationTests`
//  and the HTTP/3 suites were all one shape: `AsyncEventProbe timed out waiting for at least N
//  event(s); only M recorded`, on a *different* test each run. Six consecutive `--filter
//  HTTPTransportTests` runs failed four times, each naming a different suite, with the target's own
//  wall time swinging between 20 s and 60 s.
//
//  That is not a defect in any of those tests. `HTTPTransportTests` runs 68 tests across 15 suites in
//  parallel, each holding real sockets and (mostly) a real TLS handshake, and every one of those probes
//  was racing a two-second deadline calibrated on an idle machine.
//
//  The deeper mistake is what the deadline was *for*. Not one of the 61 `wait(forAtLeast:)` call sites
//  asserts that its event arrives quickly; they assert it arrives at all. The timeout exists solely to
//  turn a hang into a diagnosable failure — a liveness guard. Two seconds is a latency budget wearing a
//  liveness guard's clothes, and it fails exactly when the machine is busy, which is when tests run.
//
//  So the budget here is deliberately large, and scalable from the environment for loaded CI runners,
//  without editing 61 call sites — and, more to the point, without any of those sites having to make a
//  judgement about timing that it has no business making.
//

internal import Foundation

/// The real-time budget async test helpers race against, and the one knob that widens it.
///
/// Every budget is a *liveness* guard: it exists to turn a hang into a failure that names the stalled
/// probe, never to assert that an event arrives quickly. Scale it with `HTTP_TEST_TIMEOUT_SCALE`
/// (a multiplier, default `1`) on hosts where the suite contends for CPU.
public enum TestLivenessBudget {
    /// The *unscaled* budget for a helper whose caller expressed no preference.
    ///
    /// Nominal, not resolved: pass it (or any explicit budget) through ``scaled(_:)`` at the point of
    /// use, so a call site cannot express a budget that the environment knob then fails to widen.
    ///
    /// Long enough that reaching it means something is genuinely wedged rather than merely slow. The
    /// slowest legitimate observation in this suite is a TLS handshake over loopback under full
    /// parallelism — low hundreds of milliseconds when the machine is idle, and still losing a
    /// two-second race when it is not.
    public static let nominal = Duration.seconds(30)

    /// The *unscaled* budget for asserting that an event does **not** arrive.
    ///
    /// The only legitimately short budget, and the mirror image of ``nominal``: a positive wait is a
    /// liveness guard and should be as generous as patience allows, while a negative wait pays its
    /// whole budget on every successful run and so must not be. It is a weaker assertion by nature —
    /// "nothing arrived in this window", not "nothing will" — and lengthening it does not make it
    /// stronger, only slower. Reach for it *only* under `#expect(throws: AsyncEventProbeTimeoutError)`.
    public static let absence = Duration.seconds(2)

    /// The budget a polling helper should use between re-checks.
    ///
    /// Unscaled — widening the *interval* would only make a stalled test slower to diagnose. It is the
    /// total budget that has to absorb host load, which ``nominal`` does.
    public static let pollInterval = Duration.milliseconds(5)

    /// How many ``pollInterval`` re-checks fit in the resolved ``nominal`` budget.
    ///
    /// Derived rather than written down, so raising the budget or the scale cannot leave a poll loop
    /// still counting to a number chosen for the old one — which is exactly how seventeen copies of
    /// the same loop ended up with three different budgets.
    public static let pollCount: Int = {
        let total = scaled(nominal) / pollInterval
        return max(1, Int(total.rounded(.up)))
    }()

    /// The multiplier read once from `HTTP_TEST_TIMEOUT_SCALE`, clamped to at least `1`.
    ///
    /// Clamped upward only: a run that *shortens* liveness budgets would reintroduce the very failure
    /// mode this type exists to remove, and no CI configuration has a legitimate reason to ask for it.
    public static let scale: Double = {
        guard
            let raw = ProcessInfo.processInfo.environment["HTTP_TEST_TIMEOUT_SCALE"],
            let parsed = Double(raw),
            parsed.isFinite
        else {
            return 1
        }
        return max(1, parsed)
    }()

    /// Widens `base` by ``scale``.
    ///
    /// Apply this to any *real-time* budget. It must not be applied to a ``TestClock`` deadline: under
    /// an injected clock there is no real time to absorb, and scaling would silently change how far a
    /// test must advance its clock.
    public static func scaled(_ base: Duration) -> Duration {
        base * scale
    }
}
