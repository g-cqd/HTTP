//
//  HTTP2ShutdownTests.swift
//  HTTP2Tests
//
//  RFC 9113 §6.8 — graceful shutdown: the engine queues a GOAWAY(NO_ERROR) naming the last processed
//  stream and reports whether streams remain in flight, so the driver can close once they drain.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 §6.8 — graceful shutdown")
struct HTTP2ShutdownTests {
    @Test("beginGracefulShutdown queues GOAWAY(NO_ERROR) naming the last processed stream")
    func goAwayNamesLastProcessedStream() throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.get(streamID: 1))  // process stream 1
        _ = connection.outboundBytes()
        connection.beginGracefulShutdown()
        let goAway = try #require(H2Wire.firstGoAway(in: connection.outboundBytes()))
        #expect(goAway.code == .noError)
        #expect(goAway.lastStreamID == HTTP2StreamID(1))
    }

    @Test("hasOpenStreams is true while a stream awaits its response, false once closed")
    func hasOpenStreamsLifecycle() throws {
        var connection = try H2Wire.handshaked()
        #expect(!connection.hasOpenStreams)  // none yet
        _ = try connection.receive(H2Wire.get(streamID: 1))  // request in, response pending → open
        #expect(connection.hasOpenStreams)
        // Responding closes the stream.
        try connection.respond(to: HTTP2StreamID(1), HTTPResponse(status: .ok))
        #expect(!connection.hasOpenStreams)
    }
}
