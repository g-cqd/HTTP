//
//  HTTP2StreamingTests.swift
//  HTTP2Tests
//
//  RFC 9113 §8.1 / §6.9 — the sans-I/O incremental response-DATA API underpinning native HTTP/2
//  streaming (S4): `respondHeaders` opens the response with HEADERS but no END_STREAM, `sendBodyChunk`
//  appends body and releases what the send window allows (the rest waits in `pending`), `endStream`
//  terminates it, and `pendingBacklog` reports the window-blocked backlog the driver gates its producer
//  on. These tests drive a forced window stall deterministically — the engine only buffers and flushes,
//  so it cannot deadlock — and assert the backlog stays bounded to one chunk across a long stream.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 §8.1 — native HTTP/2 response streaming (incremental DATA API)")
struct HTTP2StreamingTests {
    private static let stream = HTTP2StreamID(1)

    /// A handshaked connection with one completed GET on stream 1, its outbound drained, with the peer's
    /// initial stream window set to `window` octets.
    private func afterGet(window: UInt32? = nil) throws -> HTTP2Connection {
        let settings = window.map { [(id: UInt16(0x04), value: $0)] } ?? []
        var connection = try H2Wire.handshaked(clientSettings: settings)
        _ = try connection.receive(H2Wire.get(streamID: 1))
        _ = connection.outboundBytes()
        return connection
    }

    @Test("respondHeaders sends HEADERS without END_STREAM, leaving the stream open (§8.1)")
    func respondHeadersKeepsStreamOpen() throws {
        var connection = try afterGet()
        try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
        let headers = try #require(
            H2Wire.frames(in: connection.outboundBytes()).first { $0.header.type == .headers })
        #expect(!headers.header.flags.contains(.endStream))  // stays open for incremental DATA
    }

    @Test("a body chunk past the send window defers, then a WINDOW_UPDATE releases it (§6.9)")
    func chunkStallsThenFlushesOnWindowUpdate() throws {
        var connection = try afterGet(window: 5)  // 5-octet initial stream window
        try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
        _ = connection.outboundBytes()  // drain HEADERS

        try connection.sendBodyChunk(to: Self.stream, Array("helloworld".utf8))
        #expect(H2Wire.dataPayload(in: connection.outboundBytes()).bytes == Array("hello".utf8))
        #expect(connection.pendingBacklog(of: Self.stream) == 5)  // "world" stalled on the window

        // No deadlock — the engine simply holds the remainder until the window reopens (§6.9).
        _ = try connection.receive(H2Wire.windowUpdate(streamID: 1, increment: 5))
        #expect(H2Wire.dataPayload(in: connection.outboundBytes()).bytes == Array("world".utf8))
        #expect(connection.pendingBacklog(of: Self.stream) == 0)
    }

    @Test("endStream rides the final buffered DATA frame with END_STREAM (§8.1)")
    func endStreamRidesFinalData() throws {
        var connection = try afterGet()
        try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
        try connection.sendBodyChunk(to: Self.stream, Array("data".utf8))
        try connection.endStream(to: Self.stream)
        let out = H2Wire.dataPayload(in: connection.outboundBytes())
        #expect(out.bytes == Array("data".utf8))
        #expect(out.endStream)
    }

    @Test("endStream with no buffered body emits an empty END_STREAM DATA frame (§8.1)")
    func endStreamEmptyBody() throws {
        var connection = try afterGet()
        try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
        _ = connection.outboundBytes()
        try connection.endStream(to: Self.stream)
        let out = H2Wire.dataPayload(in: connection.outboundBytes())
        #expect(out.bytes.isEmpty)
        #expect(out.endStream)  // a 0-length DATA frame carries END_STREAM
    }

    @Test("reusing an empty-END_STREAM-closed stream id is a STREAM_CLOSED connection error (§5.1)")
    func reuseAfterEmptyEndStreamIsStreamClosed() throws {
        var connection = try afterGet()
        try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
        _ = connection.outboundBytes()
        try connection.endStream(to: Self.stream)  // empty END_STREAM closes stream 1 cleanly
        _ = connection.outboundBytes()

        // A HEADERS frame reusing id 1 is scoped by how the stream closed (RFC 9113 §5.1): the empty
        // END_STREAM fast path must record the clean close, so the reuse is a connection STREAM_CLOSED
        // — not the idle-id PROTOCOL_ERROR a missing close-reason record would mis-report.
        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(H2Wire.get(streamID: 1))
        }
        catch {
            thrown = error.code  // `receive` uses typed throws, so `error` is already an HTTP2Error
        }
        #expect(thrown == .streamClosed)
    }

    @Test("a long streamed response survives a repeated window stall with bounded backlog (§6.9)")
    func streamSurvivesWindowStallBounded() throws {
        // 5-octet stream window vs 10-octet chunks: every chunk half-flushes, stalling 5 octets until a
        // WINDOW_UPDATE — so the backlog never exceeds one chunk, proving bounded memory under stall.
        var connection = try afterGet(window: 5)
        try connection.respondHeaders(to: Self.stream, HTTPResponse(status: .ok))
        _ = connection.outboundBytes()

        var received: [UInt8] = []
        for index in 0 ..< 20 {
            let chunk = [UInt8](repeating: UInt8(0x41 + (index % 26)), count: 10)
            try connection.sendBodyChunk(to: Self.stream, chunk)
            received += H2Wire.dataPayload(in: connection.outboundBytes()).bytes
            #expect(connection.pendingBacklog(of: Self.stream) <= 10)  // bounded to one chunk
            _ = try connection.receive(H2Wire.windowUpdate(streamID: 1, increment: 10))
            received += H2Wire.dataPayload(in: connection.outboundBytes()).bytes
        }
        try connection.endStream(to: Self.stream)
        let tail = H2Wire.dataPayload(in: connection.outboundBytes())
        received += tail.bytes
        #expect(received.count == 200)
        #expect(tail.endStream)
    }
}
