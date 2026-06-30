//
//  HTTP2RouteBodyLimitTests.swift
//  HTTP2Tests
//
//  Per-route request-body limit on the HTTP/2 engine (Phase 1.2, RFC 9110 §15.5.14): the connection
//  resolves the matched route's limit from the request head and caps the stream's buffered body to it —
//  tighter than the global ``HTTPLimits/maxBodySize`` — rejecting an over-limit body with
//  `RST_STREAM(ENHANCE_YOUR_CALM)` before it is fully buffered. Boundary-exact.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9110 §15.5.14 — HTTP/2 per-route body limit")
struct HTTP2RouteBodyLimitTests {
    /// A resolver that caps every route at four octets.
    private let fourOctetLimit: @Sendable (HTTPRequest) -> Int? = { _ in 4 }

    @Test("a stream body over the route limit is reset, even when within the global limit")
    func overRouteLimit() throws {
        var connection = try H2Wire.handshaked(
            limits: HTTPLimits(maxBodySize: 1_000), resolveBodyLimit: fourOctetLimit
        )
        H2Wire.expectStreamError(
            .enhanceYourCalm,
            on: 1,
            feeding: H2Wire.openStream(streamID: 1)
                + H2Wire.data(streamID: 1, payload: [UInt8](repeating: 0x61, count: 5)),
            connection: &connection
        )
    }

    @Test("a stream body exactly at the route limit is delivered (inclusive bound)")
    func atRouteLimit() throws {
        var connection = try H2Wire.handshaked(
            limits: HTTPLimits(maxBodySize: 1_000), resolveBodyLimit: fourOctetLimit
        )
        H2Wire.expectRequest(
            H2Wire.openStream(streamID: 1)
                + H2Wire.data(streamID: 1, payload: [UInt8](repeating: 0x61, count: 4)),
            on: &connection
        )
    }
}
