//
//  HTTP3ResponseStreamTests.swift
//  HTTP3Tests
//
//  RFC 9114 §4.1 — the native response-streaming engine API (P6b). Unlike `respond`, which frames the
//  whole response and FINs the stream at once, `respondHeaders` frames only the QPACK HEADERS block
//  (returning the bytes for the driver to send `fin:false`) and `dataFrame` wraps each body chunk as a
//  DATA frame — so a `ResponseStream` can drive a QUIC stream incrementally, the driver appending the
//  empty FIN at the end. These tests assert the framing in isolation and that the head + chunks
//  reassemble to exactly the response the buffered path would have produced.
//

import HTTPCore
import QPACK
import Testing

@testable import HTTP3

@Suite("RFC 9114 §4.1 — HTTP/3 native response streaming")
struct HTTP3ResponseStreamTests: HTTP3WireFixtures {
    private static let stream = QUICStreamID(0)  // client-initiated bidirectional request stream

    /// A connection with a single completed GET on ``stream`` and its request-path actions drained,
    /// ready for a streaming response.
    private func afterRequest() throws -> HTTP3Connection {
        var connection = HTTP3Connection()
        _ = try connection.receive(Self.stream, requestStream(requestFieldSection()), fin: true)
        _ = connection.outbound()  // drain request-path actions to isolate later assertions
        return connection
    }

    @Test("respondHeaders frames the QPACK HEADERS block and queues no action (no FIN, no body)")
    func respondHeadersFramesHeadOnly() throws {
        var connection = try afterRequest()
        let headerBytes = try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
        // The head alone decodes to the status, with no DATA — the body streams separately.
        let decoded = try decodeResponse(headerBytes)
        #expect(decoded.status == "200")
        #expect(decoded.body.isEmpty)
        // Unlike `respond` (which queues a `.send(…, fin: true)`), `respondHeaders` returns the bytes
        // out-of-band for the driver to send and FIN itself — so the engine queues nothing.
        #expect(connection.outbound().isEmpty)
    }

    @Test("respondHeaders removes the stream from tracking — a second call throws (§4.1)")
    func respondHeadersUntracksStream() throws {
        var connection = try afterRequest()
        _ = try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
        do {
            _ = try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
            Issue.record("expected a throw on the now-untracked stream")
        }
        catch {
            #expect(error.code == HTTP3ErrorCode.h3InternalError.rawValue)
        }
    }

    @Test("respondHeaders on an unknown stream is H3_INTERNAL_ERROR (§4.1)")
    func respondHeadersUnknownStream() {
        var connection = HTTP3Connection()
        do {
            _ = try connection.respondHeaders(to: QUICStreamID(4), HTTPResponse(status: .ok))
            Issue.record("expected a throw for an unknown stream")
        }
        catch {
            #expect(error.code == HTTP3ErrorCode.h3InternalError.rawValue)
        }
    }

    @Test("dataFrame wraps a chunk as a well-formed HTTP/3 DATA frame (§7.2.1)")
    func dataFrameFramesChunk() throws {
        let framed = HTTP3Connection.dataFrame(Array("chunk".utf8))
        let decoded = try decodeResponse(framed)
        #expect(decoded.status == nil)  // a DATA frame alone carries no HEADERS
        #expect(decoded.body == Array("chunk".utf8))
    }

    @Test("an empty chunk still frames as a zero-length DATA frame (the producer may yield one)")
    func dataFrameFramesEmptyChunk() throws {
        // The DATA type + a zero length, no payload — a valid frame the decoder accepts as empty body.
        #expect(HTTP3Connection.dataFrame([]) == frame(.data, []))
        #expect(try decodeResponse(HTTP3Connection.dataFrame([])).body.isEmpty)
    }

    @Test("HEADERS + per-chunk DATA reassemble to the full response on the wire (§4.1)")
    func streamedWireRoundTrips() throws {
        var connection = try afterRequest()
        // The exact byte sequence the native streaming path emits: HEADERS (sent fin:false), then one
        // DATA frame per produced chunk; the trailing empty FIN frame carries no bytes, so the
        // concatenation below is the whole response body on the wire.
        var wire = try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
        wire += HTTP3Connection.dataFrame(Array("hello ".utf8))
        wire += HTTP3Connection.dataFrame(Array("h3".utf8))
        let decoded = try decodeResponse(wire)
        #expect(decoded.status == "200")
        #expect(decoded.body == Array("hello h3".utf8))
    }
}
