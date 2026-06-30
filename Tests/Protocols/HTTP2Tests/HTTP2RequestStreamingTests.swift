//
//  HTTP2RequestStreamingTests.swift
//  HTTP2Tests
//
//  True-incremental request-body streaming on the HTTP/2 engine (Phase 1.4, RFC 9113 §8.1): a route that
//  opts into streaming (resolved from the head via `resolveStreamsBody`) surfaces its body as
//  `requestHead` → `requestBodyChunk`* → `requestEnd` as the DATA frames arrive, rather than buffering it
//  whole and surfacing a single `request`. Every other route is byte-for-byte unchanged (one buffered
//  `request`), and the per-route body limit (Phase 1.2) still bounds a streaming upload.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("Phase 1.4 — HTTP/2 incremental request streaming")
struct HTTP2RequestStreamingTests {
    private let streaming: @Sendable (HTTPRequest) -> Bool = { _ in true }

    @Test("a streaming route surfaces head, then each body chunk, then end — incrementally")
    func incrementalDelivery() throws {
        var connection = try H2Wire.handshaked(resolveStreamsBody: streaming)
        // HEADERS without END_STREAM: the head surfaces before any body arrives.
        let head = try connection.receive(H2Wire.openStream(streamID: 1))
        guard case .requestHead(let id, let request) = head.first, head.count == 1 else {
            Issue.record("expected a lone requestHead, got \(head)")
            return
        }
        #expect(id == HTTP2StreamID(1))
        #expect(request.method == .post)
        // A DATA frame with END_STREAM: the chunk surfaces as it arrives, then the body ends.
        let rest = try connection.receive(
            H2Wire.data(streamID: 1, payload: Array("hello".utf8))
        )
        #expect(
            rest == [
                .requestBodyChunk(streamID: HTTP2StreamID(1), bytes: Array("hello".utf8)),
                .requestEnd(streamID: HTTP2StreamID(1))
            ]
        )
    }

    @Test("a non-streaming route still surfaces one buffered request (regression)")
    func nonStreamingBuffers() throws {
        var connection = try H2Wire.handshaked()
        let events = try connection.receive(
            H2Wire.openStream(streamID: 1) + H2Wire.data(streamID: 1, payload: Array("hi".utf8))
        )
        guard case .request(_, _, let body) = events.first, events.count == 1 else {
            Issue.record("expected one buffered request, got \(events)")
            return
        }
        #expect(body == Array("hi".utf8))
    }

    @Test("the per-route body limit still resets an over-limit streaming body (Phase 1.2)")
    func streamingHonorsRouteLimit() throws {
        var connection = try H2Wire.handshaked(
            limits: HTTPLimits(maxBodySize: 1_000),
            resolveBodyLimit: { _ in 4 },
            resolveStreamsBody: streaming
        )
        H2Wire.expectStreamError(
            .enhanceYourCalm,
            on: 1,
            feeding: H2Wire.openStream(streamID: 1)
                + H2Wire.data(streamID: 1, payload: [UInt8](repeating: 0x61, count: 5)),
            connection: &connection
        )
    }
}
