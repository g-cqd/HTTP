//
//  HTTP3RouteBodyLimitTests.swift
//  HTTP3Tests
//
//  Per-route request-body limit on the HTTP/3 engine (Phase 1.2, RFC 9110 §15.5.14): the connection
//  resolves the matched route's limit from the request head and caps the stream's buffered body to it —
//  tighter than the global ``HTTPLimits/maxBodySize`` — resetting an over-limit stream with
//  `H3_REQUEST_REJECTED` before the body is fully buffered. Boundary-exact.
//

import HTTPCore
import QPACK
import Testing

@testable import HTTP3

@Suite("RFC 9110 §15.5.14 — HTTP/3 per-route body limit")
struct HTTP3RouteBodyLimitTests: HTTP3WireFixtures {
    private static let stream = QUICStreamID(0)

    private let fourOctetLimit: @Sendable (HTTPRequest) -> Int? = { _ in 4 }
    private let fiveOctetLimit: @Sendable (HTTPRequest) -> Int? = { _ in 5 }

    @Test("a body over the route limit resets the stream, even within the global limit")
    func overRouteLimit() throws {
        var connection = HTTP3Connection(
            limits: HTTPLimits(maxBodySize: 1_000), resolveBodyLimit: fourOctetLimit
        )
        let section = requestFieldSection(
            method: "POST", extra: [HeaderField(name: "content-length", value: "5")]
        )
        _ = try connection.receive(
            Self.stream, requestStream(section, body: Array("hello".utf8)), fin: true
        )
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3RequestRejected.rawValue)
    }

    @Test("a body exactly at the route limit is delivered (inclusive bound)")
    func atRouteLimit() throws {
        var connection = HTTP3Connection(
            limits: HTTPLimits(maxBodySize: 1_000), resolveBodyLimit: fiveOctetLimit
        )
        let section = requestFieldSection(
            method: "POST", extra: [HeaderField(name: "content-length", value: "5")]
        )
        let events = try connection.receive(
            Self.stream, requestStream(section, body: Array("hello".utf8)), fin: true
        )
        guard case .request(_, _, let body) = events.first else {
            Issue.record("expected a request event")
            return
        }
        #expect(body == Array("hello".utf8))
    }
}
