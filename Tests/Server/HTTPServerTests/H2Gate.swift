//
//  H2Gate.swift
//  HTTPServerTests
//
//  A handshaked ``HTTP2ConnectionState`` plus the frames to open and fill a gated stream, for the tests
//  that exercise the consumer's decisions directly rather than through a whole serve loop.
//
//  The stall sweeper's rule is a pure function of byte progress, so it is worth testing without a clock
//  or a connection at all; this is the minimum scaffolding that needs.
//
//  It hands back the whole ``HTTP2ConnectionState`` rather than a bare ``HTTP2Connection`` because the
//  engine and the plan table are not two things (audit R5-SEC1b). `serveHTTP2` builds the table FIRST
//  and closes the engine's `resolveRoute` over it, so every head that decodes files a ``DispatchPlan``
//  against its stream; a test that paired a fresh `HTTP2DispatchPlans()` with an engine whose
//  `resolveRoute` ignored it produced a state that cannot exist in production — every plan lookup missed
//  — and that is precisely why the split-generation bug on the Extended CONNECT path went uncovered for
//  three rounds of review. Constructing the pair is now impossible to get wrong because the pair is not
//  constructible separately.
//

import HTTP2
import HTTPCore

@testable import HTTPServer

/// Sans-I/O scaffolding for the ``HTTP2ConnectionState`` unit tests.
enum H2Gate {
    /// A connection state past the preface + SETTINGS handshake, with its outbound preface drained.
    ///
    /// Wired exactly as ``HTTPServer/serveHTTP2(_:deadline:initialBytes:)`` wires it: the limits and the
    /// responder generation both come from `server`, and the engine's `resolveRoute` reads
    /// ``HTTPServer/currentSnapshot`` per head and files the resulting plan — so a reload staged between
    /// a head and its dispatch is observed here the same way the serve loop observes it.
    ///
    /// `connectProtocol` advertises SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441 §3), without which the
    /// engine rejects an Extended CONNECT instead of surfacing it.
    ///
    /// `streaming` is the ONE deliberate divergence from the serve loop: it forces the incremental-body
    /// policy on for tests that drive a path no route declares. The plan filed is still the real one, so
    /// the divergence is confined to the body policy and never to the generation.
    static func state<C: Clock>(
        for server: HTTPServer<C>,
        streaming: Bool = false,
        connectProtocol: Bool = false
    ) throws -> HTTP2ConnectionState where C.Duration == Duration {
        let limits = server.limits
        var settings = HTTP2Settings()
        settings.enableConnectProtocol = connectProtocol
        settings.initialWindowSize = limits.streamReceiveWindow
        let plans = HTTP2DispatchPlans()
        let resolveRoute: @Sendable (HTTP2StreamID, HTTPRequest) -> RequestBodyPolicy = {
            streamID, request in
            let snapshot = server.currentSnapshot
            let plan = DispatchPlan(
                snapshot: snapshot,
                match: snapshot.resolver?
                    .match(method: request.method, path: request.path, isUpgrade: false)
            )
            plans.file(plan, for: streamID)
            return RequestBodyPolicy(
                limit: plan.bodyLimit,
                isStreaming: streaming || plan.streamsBody
            )
        }
        var connection = HTTP2Connection(
            localSettings: settings,
            limits: limits,
            resolveRoute: resolveRoute
        )
        _ = connection.outboundBytes()
        _ = try connection.receive(H2ServerWire.preface + H2ServerWire.settings())
        _ = connection.outboundBytes()
        return HTTP2ConnectionState(engine: connection, plans: plans)
    }

    /// HEADERS opening `streamID` for a streaming route, plus `count` octets of DATA on it.
    static func openAndFill(streamID: HTTP2StreamID, count: Int) -> [UInt8] {
        H2ServerWire.headers(streamID: streamID.rawValue, path: "/upload")
            + H2ServerWire.dataFrames(streamID: streamID.rawValue, total: count)
    }
}
