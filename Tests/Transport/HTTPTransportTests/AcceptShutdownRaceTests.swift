//
//  AcceptShutdownRaceTests.swift
//  HTTPTransportTests
//
//  Audit FLAKE-1's original symptom, finally named: an intermittent SIGTRAP in
//  `AcceptBackpressureTests` under `--parallel`, in `POSIXDispatchTransport.shutdown()` at
//  `_dispatch_queue_xref_dispose` — libdispatch's trap for releasing a **suspended** dispatch source.
//
//  `POSIXDispatchTransport` suspends its accept read source when admission saturates and resumes it on
//  the hysteresis edge, balanced 1:1 by a flag, because an unbalanced `resume()` also traps. The three
//  transitions all ran on `acceptQueue` and were therefore serialized against each other. `shutdown()`
//  issues the balancing `resume()` too — and ran wherever it was awaited.
//
//  The flag and the source live under two *different* mutexes, and the `suspend()` / `resume()` calls
//  happen outside both. So an accept handler that had set the flag and not yet suspended could be
//  overtaken by a shutdown that read "suspended", resumed a source still running (trap #1), then
//  cancelled it — leaving the handler to suspend a source about to be released (trap #2).
//
//  **What this test does not do: reproduce that interleaving.** The first version of it tried, by
//  shutting the transport down at the moment the ceiling bites, twelve rounds per backbone. Measured
//  against the unfixed source it passed 8 runs out of 8 — the window is a few instructions wide and
//  driving it from outside is wishful thinking. Shipping that as a regression test would have been
//  the `fin: true` mistake this audit already made once: a test that exercises the easy path and
//  reads as coverage.
//
//  What it does instead is drive `shutdown()` against a *suspended* accept source on every gated
//  backbone, which is enough to make the invariant machine-checkable. `balanceAndCancel` asserts its
//  queue with `dispatchPrecondition`, so moving that work back off `acceptQueue` — the exact shape
//  that produced the SIGTRAP — trips on the first shutdown rather than one run in six. Verified by
//  mutation: with the hop removed, this suite kills the process on the `.posixDispatch` case.
//
//  The guarantee is therefore structural, not statistical, and the test exists to keep the structure
//  reachable rather than to catch the race by luck.
//

import Darwin
import HTTPTestSupport
import Testing

@testable import HTTPTransport

@Suite("Transport — shutdown racing accept suspension (audit FLAKE-1)", .realNetwork)
struct AcceptShutdownRaceTests {
    /// Small enough that a handful of loopback connections saturates it immediately.
    private static let capacity = 2

    @Test(
        "shutting down while the accept source is suspended neither traps nor hangs",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)),
        arguments: AcceptBackpressureTests.gatedBackbones
    )
    func shutdownDuringAdmissionSuspension(_ backbone: TransportBackbone) async throws {
        // A handful of rounds, not because repetition makes the race likely — it measurably does not
        // — but because saturation is the *precondition* for reaching the balancing `resume()`, and a
        // single round leaves that to a scheduling coincidence.
        for _ in 0 ..< 4 {
            let gate = ConnectionAdmission(
                capacity: ConnectionAdmission.Capacity(total: Self.capacity, perHost: 1_000)
            )
            let transport = try TransportFactory.make(
                TransportConfiguration(port: 0, backbone: backbone, eventLoopCount: 1)
            )
            let stream = try await transport.start(admission: gate)
            let port = transport.boundPort
            try #require(port != 0)

            // Nobody drains `stream`: the gate saturates and the source suspends, which is the state
            // shutdown has to unwind. Well past the ceiling so saturation is not a matter of timing.
            let clients = (0 ..< Self.capacity * 4).map { _ in openLoopbackConnection(to: port) }
            defer {
                for descriptor in clients where descriptor >= 0 {
                    close(descriptor)
                }
            }

            await transport.shutdown()
            _ = stream
        }
    }
}
