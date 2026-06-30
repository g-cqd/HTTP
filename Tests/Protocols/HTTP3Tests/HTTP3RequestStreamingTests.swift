//
//  HTTP3RequestStreamingTests.swift
//  HTTP3Tests
//
//  True-incremental request-body streaming on the HTTP/3 engine (Phase 1.4, RFC 9114 §4): a route that
//  opts into streaming (resolved from the head via `resolveStreamsBody`) surfaces its body as
//  `requestHead` → `requestBodyChunk`* → `requestEnd` as the DATA frames arrive, rather than buffering it
//  whole and surfacing a single `request`. Every other route is byte-for-byte unchanged (one buffered
//  `request`), and the per-route body limit (Phase 1.2) still bounds a streaming upload.
//

import HTTPCore
import QPACK
import Testing

@testable import HTTP3

@Suite("Phase 1.4 — HTTP/3 incremental request streaming")
struct HTTP3RequestStreamingTests: HTTP3WireFixtures {
    private static let stream = QUICStreamID(0)
    private let streaming: @Sendable (HTTPRequest) -> Bool = { _ in true }

    @Test("a streaming route surfaces head, then each body chunk, then end — incrementally")
    func incrementalDelivery() throws {
        var connection = HTTP3Connection(resolveStreamsBody: streaming)
        let section = requestFieldSection(method: "POST")
        // HEADERS alone (no FIN): the head surfaces before any body arrives.
        let head = try connection.receive(Self.stream, frame(.headers, section), fin: false)
        guard case .requestHead(_, let request) = head.first, head.count == 1 else {
            Issue.record("expected a lone requestHead, got \(head)")
            return
        }
        #expect(request.method == .post)
        // A DATA frame (no FIN): the chunk surfaces as it arrives, not buffered until the end.
        let chunk = try connection.receive(
            Self.stream, frame(.data, Array("hello".utf8)), fin: false
        )
        #expect(chunk == [.requestBodyChunk(streamID: Self.stream, bytes: Array("hello".utf8))])
        // FIN: the body ends.
        let end = try connection.receive(Self.stream, [], fin: true)
        #expect(end == [.requestEnd(streamID: Self.stream)])
    }

    @Test("a HEADERS+DATA+FIN delivered together still splits into head, chunk, end")
    func combinedBatchSplits() throws {
        var connection = HTTP3Connection(resolveStreamsBody: streaming)
        let section = requestFieldSection(method: "POST")
        let events = try connection.receive(
            Self.stream, requestStream(section, body: Array("hi".utf8)), fin: true
        )
        guard case .requestHead = events.first else {
            Issue.record("expected requestHead first, got \(events)")
            return
        }
        #expect(events.contains(.requestBodyChunk(streamID: Self.stream, bytes: Array("hi".utf8))))
        #expect(events.last == .requestEnd(streamID: Self.stream))
    }

    @Test("a non-streaming route still surfaces one buffered request (regression)")
    func nonStreamingBuffers() throws {
        var connection = HTTP3Connection()  // default resolveStreamsBody → false
        let section = requestFieldSection(method: "POST")
        let events = try connection.receive(
            Self.stream, requestStream(section, body: Array("hi".utf8)), fin: true
        )
        guard case .request(_, _, let body) = events.first, events.count == 1 else {
            Issue.record("expected one buffered request, got \(events)")
            return
        }
        #expect(body == Array("hi".utf8))
    }

    @Test("the per-route body limit still rejects an over-limit streaming body (Phase 1.2)")
    func streamingHonorsRouteLimit() throws {
        var connection = HTTP3Connection(
            limits: HTTPLimits(maxBodySize: 1_000),
            resolveBodyLimit: { _ in 4 },
            resolveStreamsBody: streaming
        )
        let section = requestFieldSection(method: "POST")
        _ = try connection.receive(Self.stream, frame(.headers, section), fin: false)
        _ = try? connection.receive(Self.stream, frame(.data, Array("toolong".utf8)), fin: false)
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3RequestRejected.rawValue)
    }
}
