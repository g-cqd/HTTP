//
//  H2SpecFrameDefinitionTests.swift
//  HTTP2Tests
//
//  h2spec conformance — the `http2` group, RFC 7540/9113 §6 Frame Definitions, part 1: §6.1 DATA,
//  §6.2 HEADERS, §6.3 PRIORITY, §6.4 RST_STREAM. (SETTINGS/PING/GOAWAY are in H2SpecSettingsTests;
//  WINDOW_UPDATE/CONTINUATION in H2SpecFlowControlTests.) Each case asserts the connection- or
//  stream-scoped reaction the RFC mandates for a malformed or misplaced frame.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

@Suite("h2spec http2 §6.1–6.4 — Frame Definitions (DATA/HEADERS/PRIORITY/RST_STREAM)")
struct H2SpecFrameDefinitionTests {
    // MARK: §6.1 DATA

    @Test("6.1/1 — a DATA frame with stream identifier 0x0 is a PROTOCOL_ERROR (§6.1)")
    func dataOnStreamZeroIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.data(streamID: 0, payload: [0x61], endStream: false),
            on: &connection
        )
    }

    @Test("6.1/2 — a DATA frame on a non-open stream is a STREAM_CLOSED stream error (§6.1)")
    func dataOnNonOpenStreamIsStreamClosed() throws {
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

    @Test("6.1/3 — a DATA frame with an invalid pad length is a PROTOCOL_ERROR (§6.1)")
    func dataWithInvalidPadLengthIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        // PADDED with a pad-length octet (0xFF) larger than the rest of the payload.
        wire += H2Wire.frame(
            .data,
            flags: [.padded, .endStream],
            streamID: 1,
            payload: [0xFF, 0x61]
        )
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    // MARK: §6.2 HEADERS

    @Test(
        "6.2/1 — a HEADERS frame without END_HEADERS, then a PRIORITY frame, is a PROTOCOL_ERROR (§6.2)"
    )
    func headersWithoutEndHeadersThenPriorityIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(),
            endStream: false,
            endHeaders: false
        )
        wire += H2Wire.priority(streamID: 1, dependency: 0)
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    @Test(
        "6.2/2 — a HEADERS frame for another stream while sending a HEADERS is a PROTOCOL_ERROR (§6.2)"
    )
    func headersForAnotherStreamIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(),
            endStream: false,
            endHeaders: false
        )
        wire += H2Wire.headers(streamID: 3, fields: H2Wire.requestFields())
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    @Test("6.2/3 — a HEADERS frame with stream identifier 0x0 is a PROTOCOL_ERROR (§6.2)")
    func headersOnStreamZeroIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.headers(streamID: 0, fields: H2Wire.requestFields()),
            on: &connection
        )
    }

    @Test("6.2/4 — a HEADERS frame with an invalid pad length is a PROTOCOL_ERROR (§6.2)")
    func headersWithInvalidPadLengthIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        // PADDED with a pad length (0xFF) larger than the remaining payload after the block.
        var payload: [UInt8] = [0xFF]
        payload += H2Wire.headerBlock(H2Wire.requestFields())
        let wire = H2Wire.frame(
            .headers,
            flags: [.padded, .endHeaders, .endStream],
            streamID: 1,
            payload: payload
        )
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    // MARK: §6.3 PRIORITY

    @Test("6.3/1 — a PRIORITY frame with stream identifier 0x0 is a PROTOCOL_ERROR (§6.3)")
    func priorityOnStreamZeroIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.priority(streamID: 0, dependency: 0),
            on: &connection
        )
    }

    @Test("6.3/2 — a PRIORITY frame with a length other than 5 octets is a FRAME_SIZE_ERROR (§6.3)")
    func priorityWithWrongLengthIsStreamFrameSizeError() throws {
        var connection = try H2Wire.handshaked()
        // §6.3 scopes a bad-size PRIORITY to the stream, not the connection (RFC 9113 §6.3).
        let wire = H2Wire.frame(.priority, streamID: 1, payload: [0x00, 0x00, 0x00, 0x00])  // 4 ≠ 5
        H2Wire.expectStreamError(.frameSizeError, on: 1, feeding: wire, connection: &connection)
    }

    // MARK: §6.4 RST_STREAM

    @Test("6.4/1 — an RST_STREAM frame with stream identifier 0x0 is a PROTOCOL_ERROR (§6.4)")
    func resetOnStreamZeroIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.rstStream(streamID: 0),
            on: &connection
        )
    }

    @Test("6.4/2 — an RST_STREAM frame on an idle stream is a PROTOCOL_ERROR (§6.4)")
    func resetOnIdleStreamIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.rstStream(streamID: 1),
            on: &connection
        )
    }

    @Test(
        "6.4/3 — an RST_STREAM frame with a length other than 4 octets is a FRAME_SIZE_ERROR (§6.4)"
    )
    func resetWithWrongLengthIsFrameSizeError() throws {
        var connection = try H2Wire.handshaked()
        // The length check precedes the stream-state check (RFC 9113 §6.4): a connection error.
        let wire = H2Wire.frame(.rstStream, streamID: 1, payload: [0x00, 0x00, 0x00])  // 3 ≠ 4
        H2Wire.expectConnectionError(.frameSizeError, feeding: wire, on: &connection)
    }

    // h2spec coverage: §6.1 (3) + §6.2 (4) + §6.3 (2) + §6.4 (3) = 12 cases.
}
