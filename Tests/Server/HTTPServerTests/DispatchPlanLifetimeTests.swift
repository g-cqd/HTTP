//
//  DispatchPlanLifetimeTests.swift
//  HTTPServerTests
//
//  A table keyed by a peer-chosen stream id is a memory bound, not a convenience: if any path that ends
//  a stream forgets to drop its entry, a long-lived connection accumulates one plan per request forever
//  (CWE-401 — missing release; CWE-770 — allocation without limits). The HTTP/2 plan table therefore
//  hangs off `HTTP2ConnectionState.retire(_:)`, the single choke point every stream ending already
//  funnels through, and these pin that it actually does.
//

import HTTP2
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Dispatch plans — a stream's plan dies with the stream (CR-F12 / CWE-770)")
struct DispatchPlanLifetimeTests {
    private static func plan() -> DispatchPlan {
        DispatchPlan(
            snapshot: ResponderSnapshot(
                ClosureResponder { _, _, _ in .text("x") }, generation: 0
            )
        )
    }

    private static func state() throws -> HTTP2ConnectionState {
        HTTP2ConnectionState(
            engine: try H2Gate.handshaked(limits: .default, streaming: false),
            plans: HTTP2DispatchPlans()
        )
    }

    @Test("retiring a stream drops the plan its head filed")
    func retireDropsThePlan() throws {
        var state = try Self.state()
        let stream = HTTP2StreamID(1)
        state.plans.file(Self.plan(), for: stream)
        #expect(state.plans.count == 1)
        state.retire(stream)
        #expect(state.plans.isEmpty)
    }

    @Test("a peer reset drops the plan too — the reset path funnels through retire (audit F6)")
    func resetDropsThePlan() async throws {
        var state = try Self.state()
        let stream = HTTP2StreamID(1)
        state.plans.file(Self.plan(), for: stream)
        let server = HTTPServer(
            transport: FakeTransport(), responder: ClosureResponder { _, _, _ in .text("x") }
        )
        await server.resetHTTP2Stream(stream, state: &state)
        #expect(state.plans.isEmpty)
    }

    @Test("filing over an existing plan replaces it rather than accumulating")
    func filingReplaces() {
        let plans = HTTP2DispatchPlans()
        plans.file(Self.plan(), for: HTTP2StreamID(1))
        plans.file(Self.plan(), for: HTTP2StreamID(1))
        #expect(plans.count == 1)
    }

    @Test("a plan filed for an unregistered HTTP/3 stream is dropped, not accumulated")
    func http3RegistryFilesOnlyRegisteredStreams() {
        let registry = HTTP3StreamRegistry()
        // Nothing registered `id`: it was reset or retired while its HEADERS were still decoding.
        registry.file(Self.plan(), for: QUICStreamID(0))
        #expect(registry.plan(for: QUICStreamID(0)) == nil)
        #expect(registry.isEmpty)
    }

    @Test("retiring an HTTP/3 stream drops its plan with the registry entry")
    func http3RetireDropsThePlan() {
        let registry = HTTP3StreamRegistry()
        let stream = FakeQUICStream(id: QUICStreamID(0), direction: .bidirectional)
        registry.register(stream)
        registry.file(Self.plan(), for: stream.id)
        #expect(registry.plan(for: stream.id) != nil)
        registry.retire(stream.id)
        #expect(registry.plan(for: stream.id) == nil)
        #expect(registry.isEmpty)
    }
}
