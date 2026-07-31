//
//  HandlerExecutionAdaptiveTests.swift
//  HTTPServerTests
//
//  ``HandlerExecutionPolicy/adaptive(threshold:)`` — a route keeps the reactor's no-hop fast path
//  until its own measured service time says it should not (audit CR-F7).
//
//  Two layers, deliberately. The gate's RULE is unit-tested against an injected
//  ``MonotonicNowProvider``, so "after its measured service time exceeds the threshold" is a
//  statement about exact nanoseconds and window rollovers, with no real waiting and no timing
//  assumption whatsoever. The gate's EFFECT is then observed end to end: a handler on a
//  reactor-pinned connection asks the probe executor whether it is still on the event loop, which is
//  a direct read of where the policy put it rather than an inference from a duration.
//
//  The end-to-end arms use thresholds several orders of magnitude away from anything a host can
//  produce (`.zero` and one hour), so a loaded machine cannot flip either verdict.
//

import HTTPConcurrency
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Handler execution — .adaptive hops a route only once it measures slow (CR-F7)")
struct HandlerExecutionAdaptiveTests {
    private static let route = RouteExecutionKey.unrouted
    private static let oneMillisecond = Duration.milliseconds(1)

    private static func gate(_ threshold: Duration, _ clock: TestClock) -> HandlerExecutionGate {
        HandlerExecutionGate(threshold: threshold, now: clock.nowProvider)
    }

    // MARK: The rule, against an injected clock

    @Test("a route with no measurement yet runs inline")
    func unmeasuredRouteRunsInline() {
        #expect(!Self.gate(Self.oneMillisecond, TestClock()).hops(Self.route))
    }

    @Test("a sample at or below the threshold leaves the route inline", arguments: [0, 500, 1_000])
    func fastSampleStaysInline(microseconds: Int) {
        let gate = Self.gate(Self.oneMillisecond, TestClock())
        gate.record(Duration.microseconds(microseconds).monotonicNanoseconds, for: Self.route)
        #expect(!gate.hops(Self.route))
    }

    @Test("a sample above the threshold moves the route off the reactor")
    func slowSampleHops() {
        let gate = Self.gate(Self.oneMillisecond, TestClock())
        gate.record(Duration.microseconds(1_001).monotonicNanoseconds, for: Self.route)
        #expect(gate.hops(Self.route))
    }

    @Test("a fast sample does not undo a slow one inside the same window")
    func aFastSampleDoesNotFlipMidWindow() {
        let clock = TestClock()
        let gate = Self.gate(Self.oneMillisecond, clock)
        gate.record(Duration.milliseconds(50).monotonicNanoseconds, for: Self.route)
        clock.advance(by: HandlerExecutionGate.evaluationInterval / 2)
        gate.record(Duration.microseconds(10).monotonicNanoseconds, for: Self.route)
        #expect(gate.hops(Self.route), "one fast request erased the evidence of a slow one")
    }

    @Test("a route that becomes fast again returns to the inline path")
    func fastAgainRevertsAfterAQuietWindow() {
        let clock = TestClock()
        let gate = Self.gate(Self.oneMillisecond, clock)
        gate.record(Duration.milliseconds(50).monotonicNanoseconds, for: Self.route)
        #expect(gate.hops(Self.route))

        // Crossing into the next window adopts the window that saw the slow sample as its verdict,
        // so the route still hops here — this is the hysteresis, not a bug.
        clock.advance(by: HandlerExecutionGate.evaluationInterval * 2)
        gate.record(Duration.microseconds(10).monotonicNanoseconds, for: Self.route)
        #expect(gate.hops(Self.route))

        // The window just closed contained only fast samples, so the next one runs inline again.
        clock.advance(by: HandlerExecutionGate.evaluationInterval * 2)
        gate.record(Duration.microseconds(10).monotonicNanoseconds, for: Self.route)
        #expect(!gate.hops(Self.route))
    }

    @Test("one slow route does not move a different route")
    func routesAreIndependent() throws {
        let gate = Self.gate(Self.oneMillisecond, TestClock())
        let table = Router {
            Route.get("/slow") { _, _, _ in .text("slow") }
            Route.get("/fast") { _, _, _ in .text("fast") }
        }
        let slow = try #require(RouteExecutionKey(table.match(method: .get, path: "/slow")))
        let fast = try #require(RouteExecutionKey(table.match(method: .get, path: "/fast")))
        #expect(slow != fast)

        gate.record(Duration.milliseconds(50).monotonicNanoseconds, for: slow)
        #expect(gate.hops(slow))
        #expect(!gate.hops(fast), "a slow route moved an unrelated one")
    }

    @Test("a match from a resolver that mints no handle shares the unrouted bucket")
    func handleFreeMatchesShareOneBucket() {
        let bare = RouteMatch(route: ResolvedRoute())
        #expect(RouteExecutionKey(bare) == nil)
    }

    // MARK: The effect, observed from inside the handler

    @Test(
        "the policy decides where the handler actually runs",
        arguments: [
            (HandlerExecutionPolicy.inline, [true, true, true]),
            (.concurrent, [false, false, false]),
            // An hour: no handler on any host reaches it, so the route stays inline throughout.
            (.adaptive(threshold: .seconds(3_600)), [true, true, true]),
            // Zero: the first request has nothing measured yet and runs inline; its own service time
            // is necessarily above zero, so every later request on that route hops.
            (.adaptive(threshold: .zero), [true, false, false])
        ]
    )
    func handlerObservesTheConfiguredExecutor(
        policy: HandlerExecutionPolicy,
        expected: [Bool]
    ) async {
        let executor = ReactorProbeExecutor()
        let observations = AsyncEventProbe<Bool>()
        let responder = ClosureResponder { _, _, _ in
            observations.record(executor.isCurrent)
            return .text("ok")
        }
        var wire = ""
        for index in 0 ..< expected.count {
            let last = index == expected.count - 1
            wire += "GET /probe HTTP/1.1\r\nHost: x\r\n"
            wire += last ? "Connection: close\r\n\r\n" : "\r\n"
        }
        let connection = ReactorPinnedConnection(inbound: Array(wire.utf8), executor: executor)
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: responder,
            handlerExecution: policy
        )
        // The body of the private `HTTPServer.accept(_:)` — see HandlerExecutionReactorAffinityTests.
        await withTaskExecutorPreference(connection.preferredTaskExecutor) {
            await server.serve(connection)
        }
        #expect(observations.events == expected)
    }
}
