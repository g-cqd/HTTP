//
//  H2SpecStreamTests.swift
//  HTTP2Tests
//
//  h2spec conformance — the `http2` group, RFC 7540/9113 §5 (Streams and Multiplexing): §5.1 stream
//  states (the idle/half-closed/closed frame matrix), §5.1.1 identifiers, §5.1.2 concurrency, §5.3.1
//  dependencies, §5.4.1 connection-error handling, and §5.5 extension frames.
//
//  F1 is now fixed: the engine tracks a bounded set of recently-closed stream ids, so a DATA/HEADERS
//  frame on a closed stream is the §5.1 STREAM_CLOSED *stream* error (survivable) rather than a
//  connection PROTOCOL_ERROR that tears down every multiplexed stream.
//  A lone CONTINUATION on a half-closed/closed stream is a connection PROTOCOL_ERROR here (RFC 9113
//  §6.10: a CONTINUATION with no open block has no stream context to scope to); h2spec's STREAM_CLOSED
//  expectation for that sub-case is noted inline as a defensible divergence, not a bug.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

@Suite("h2spec http2 §5 — Streams and Multiplexing")
struct H2SpecStreamTests {
    // MARK: §5.1 Stream States — idle (frames before HEADERS are a connection PROTOCOL_ERROR)

    @Test(
        "5.1/idle — DATA/RST_STREAM/WINDOW_UPDATE/CONTINUATION on an idle stream is PROTOCOL_ERROR (§5.1)",
        arguments: [
            (label: "DATA", frame: H2Wire.data(streamID: 1, payload: [0x61], endStream: false)),
            (label: "RST_STREAM", frame: H2Wire.rstStream(streamID: 1)),
            (label: "WINDOW_UPDATE", frame: H2Wire.windowUpdate(streamID: 1, increment: 1)),
            (label: "CONTINUATION", frame: H2Wire.continuation(streamID: 1))
        ])
    func idleStreamFrameIsProtocolError(_ testCase: (label: String, frame: [UInt8])) throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(.protocolError, feeding: testCase.frame, on: &connection)
    }

    // MARK: §5.1 Stream States — half closed (remote): the stream is still tracked

    @Test("5.1/half-closed-remote — DATA is a STREAM_CLOSED stream error (§5.1)")
    func halfClosedRemoteDataIsStreamClosed() throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.get(streamID: 1))  // END_STREAM → half-closed (remote)
        _ = connection.outboundBytes()
        H2Wire.expectStreamError(
            .streamClosed,
            on: 1,
            feeding: H2Wire.data(streamID: 1, payload: [0x61], endStream: true),
            connection: &connection
        )
    }

    @Test("5.1/half-closed-remote — HEADERS is a STREAM_CLOSED stream error (§5.1)")
    func halfClosedRemoteHeadersIsStreamClosed() throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.get(streamID: 1))
        _ = connection.outboundBytes()
        H2Wire.expectStreamError(
            .streamClosed,
            on: 1,
            feeding: H2Wire.headers(streamID: 1, fields: H2Wire.requestFields(), endStream: true),
            connection: &connection
        )
    }

    @Test("5.1/half-closed-remote — a lone CONTINUATION is a PROTOCOL_ERROR (RFC 9113 §6.10)")
    func halfClosedRemoteContinuationIsProtocolError() throws {
        // h2spec expects STREAM_CLOSED here; with no open header block there is no stream context to
        // scope the error to, so §6.10 makes a stray CONTINUATION a connection error. Defensible.
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.get(streamID: 1))
        _ = connection.outboundBytes()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.continuation(streamID: 1),
            on: &connection
        )
    }

    // MARK: §5.1 Stream States — closed (recently-closed ids tracked → STREAM_CLOSED, audit F1)

    @Test("5.1/closed-after-RST — DATA is a STREAM_CLOSED stream error (§5.1)")
    func closedAfterResetDataIsStreamClosed() throws {
        var connection = try H2Wire.handshaked()
        var open = H2Wire.openStream(streamID: 1)
        open += H2Wire.rstStream(streamID: 1)  // client closes the stream
        _ = try connection.receive(open)
        _ = connection.outboundBytes()
        H2Wire.expectStreamError(
            .streamClosed,
            on: 1,
            feeding: H2Wire.data(streamID: 1, payload: [0x61], endStream: true),
            connection: &connection
        )
    }

    @Test("5.1/closed-after-RST — HEADERS is a STREAM_CLOSED stream error (§5.1)")
    func closedAfterResetHeadersIsStreamClosed() throws {
        var connection = try H2Wire.handshaked()
        var open = H2Wire.openStream(streamID: 1)
        open += H2Wire.rstStream(streamID: 1)
        _ = try connection.receive(open)
        _ = connection.outboundBytes()
        H2Wire.expectStreamError(
            .streamClosed,
            on: 1,
            feeding: H2Wire.headers(streamID: 1, fields: H2Wire.requestFields()),
            connection: &connection
        )
    }

    @Test("5.1/closed — DATA after a completed response is a STREAM_CLOSED stream error (§5.1)")
    func closedStreamDataIsStreamClosed() throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.get(streamID: 1))
        _ = connection.outboundBytes()
        // A response with no body sets END_STREAM, closing the stream.
        try connection.respond(to: HTTP2StreamID(1), HTTPResponse(status: .ok))
        _ = connection.outboundBytes()
        H2Wire.expectStreamError(
            .streamClosed,
            on: 1,
            feeding: H2Wire.data(streamID: 1, payload: [0x61], endStream: true),
            connection: &connection
        )
    }

    @Test("5.1/closed — HEADERS after a completed response is a STREAM_CLOSED stream error (§5.1)")
    func closedStreamHeadersIsStreamClosed() throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.get(streamID: 1))
        _ = connection.outboundBytes()
        try connection.respond(to: HTTP2StreamID(1), HTTPResponse(status: .ok))
        _ = connection.outboundBytes()
        H2Wire.expectStreamError(
            .streamClosed,
            on: 1,
            feeding: H2Wire.headers(streamID: 1, fields: H2Wire.requestFields()),
            connection: &connection
        )
    }

    @Test(
        "5.1/closed — a lone CONTINUATION on a closed stream is a PROTOCOL_ERROR (RFC 9113 §6.10)")
    func closedStreamContinuationIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var open = H2Wire.openStream(streamID: 1)
        open += H2Wire.rstStream(streamID: 1)
        _ = try connection.receive(open)
        _ = connection.outboundBytes()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.continuation(streamID: 1),
            on: &connection
        )
    }

    // MARK: §5.1.1 Stream Identifiers

    @Test("5.1.1/1 — an even-numbered stream identifier is a PROTOCOL_ERROR (§5.1.1)")
    func evenStreamIdentifierIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.get(streamID: 2),
            on: &connection
        )
    }

    @Test("5.1.1/2 — a numerically smaller stream identifier is a PROTOCOL_ERROR (§5.1.1)")
    func decreasingStreamIdentifierIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.get(streamID: 3))
        _ = connection.outboundBytes()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.get(streamID: 1),
            on: &connection
        )
    }

    // MARK: §5.1.2 Stream Concurrency

    @Test("5.1.2/1 — exceeding SETTINGS_MAX_CONCURRENT_STREAMS is REFUSED_STREAM (§5.1.2)")
    func exceedingConcurrencyIsRefusedStream() throws {
        var connection = try H2Wire.handshaked(limits: HTTPLimits(maxConcurrentStreams: 2))
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.openStream(streamID: 3)  // at the cap of 2
        wire += H2Wire.openStream(streamID: 5)  // exceeds → refused, connection survives
        H2Wire.expectStreamError(.refusedStream, on: 5, feeding: wire, connection: &connection)
    }

    // MARK: §5.3.1 Stream Dependencies

    @Test("5.3.1/1 — a HEADERS frame that depends on itself is a stream PROTOCOL_ERROR (§5.3.1)")
    func headersSelfDependencyIsStreamError() throws {
        var connection = try H2Wire.handshaked()
        let wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(),
            priority: (exclusive: false, dependency: 1, weight: 0)
        )
        H2Wire.expectStreamError(.protocolError, on: 1, feeding: wire, connection: &connection)
    }

    @Test("5.3.1/2 — a PRIORITY frame that depends on itself is a stream PROTOCOL_ERROR (§5.3.1)")
    func prioritySelfDependencyIsStreamError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectStreamError(
            .protocolError,
            on: 1,
            feeding: H2Wire.priority(streamID: 1, dependency: 1),
            connection: &connection
        )
    }

    // MARK: §5.4.1 Connection Error Handling

    @Test("5.4.1/1 — an invalid PING frame closes the connection (§5.4.1)")
    func invalidFrameClosesConnection() throws {
        var connection = try H2Wire.handshaked()
        // A PING with a 6-octet payload (≠ 8) is a connection FRAME_SIZE_ERROR (§6.7) — the engine
        // throws, which the driver turns into a TCP close.
        H2Wire.expectConnectionError(
            .frameSizeError,
            feeding: H2Wire.ping(payload: [UInt8](repeating: 0, count: 6)),
            on: &connection,
            requireGoAway: false
        )
    }

    @Test("5.4.1/2 — a connection error first emits a GOAWAY frame (§5.4.1)")
    func connectionErrorEmitsGoAway() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .frameSizeError,
            feeding: H2Wire.ping(payload: [UInt8](repeating: 0, count: 6)),
            on: &connection,
            requireGoAway: true
        )
    }

    // MARK: §5.5 Extending HTTP/2

    @Test("5.5/1 — an unknown extension frame is ignored (§5.5)")
    func unknownExtensionFrameIsIgnored() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectAccepted(
            H2Wire.frame(HTTP2FrameType(rawValue: 0x16), streamID: 1, payload: [0xFF]),
            on: &connection
        )
        H2Wire.expectRequest(H2Wire.get(streamID: 1), on: &connection)
    }

    @Test("5.5/2 — an unknown extension frame mid header block is a PROTOCOL_ERROR (§5.5)")
    func unknownExtensionFrameInHeaderBlockIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(),
            endStream: false,
            endHeaders: false
        )
        wire += H2Wire.frame(HTTP2FrameType(rawValue: 0x16), streamID: 1, payload: [0xFF])
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    // h2spec coverage: §5.1 (13) + §5.1.1 (2) + §5.1.2 (1) + §5.3.1 (2) + §5.4.1 (2) + §5.5 (2) = 22.
}
