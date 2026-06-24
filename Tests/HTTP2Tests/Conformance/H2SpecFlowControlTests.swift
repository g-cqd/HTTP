//
//  H2SpecFlowControlTests.swift
//  HTTP2Tests
//
//  h2spec conformance — the `http2` group, RFC 7540/9113 §6.9 WINDOW_UPDATE & flow control
//  (+ §6.9.1 the flow-control window, §6.9.2 initial window size) and §6.10 CONTINUATION. These drive
//  the send-side flow controller through `respond(...)` and assert the receive-side WINDOW_UPDATE /
//  CONTINUATION framing rules.
//
//  Note: §6.9 #2 (zero increment on a stream) is asserted as a *stream* error per RFC 9113 §6.9; the
//  h2spec catalog labels it a connection error, a pre-9113 reading our engine intentionally supersedes.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("h2spec http2 §6.9/6.10 — Flow Control & CONTINUATION")
struct H2SpecFlowControlTests {
    // MARK: §6.9 WINDOW_UPDATE

    @Test("6.9/1 — a WINDOW_UPDATE with a 0 increment on the connection is a PROTOCOL_ERROR (§6.9)")
    func zeroConnectionWindowUpdateIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError, feeding: H2Wire.windowUpdate(streamID: 0, increment: 0), on: &connection
        )
    }

    @Test(
        "6.9/2 — a WINDOW_UPDATE with a 0 increment on a stream is a stream PROTOCOL_ERROR (§6.9)")
    func zeroStreamWindowUpdateIsStreamProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.windowUpdate(streamID: 1, increment: 0)
        H2Wire.expectStreamError(.protocolError, on: 1, feeding: wire, connection: &connection)
    }

    @Test("6.9/3 — a WINDOW_UPDATE with a length other than 4 octets is a FRAME_SIZE_ERROR (§6.9)")
    func windowUpdateWrongLengthIsFrameSizeError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .frameSizeError,
            feeding: H2Wire.frame(.windowUpdate, payload: [0x00, 0x00, 0x00]),
            on: &connection
        )
    }

    // MARK: §6.9.1 The Flow-Control Window

    @Test("6.9.1/1 — a flow-controlled frame never exceeds the available window (§6.9.1)")
    func dataNeverExceedsTheWindow() throws {
        // The peer advertises a 1-octet initial stream window.
        var connection = try H2Wire.handshaked(clientSettings: [(id: 0x04, value: 1)])
        _ = try connection.receive(H2Wire.get(streamID: 1))
        _ = connection.outboundBytes()
        try connection.respond(
            to: HTTP2StreamID(1),
            HTTPResponse(status: .ok),
            body: Array("hello".utf8)
        )
        let data = H2Wire.dataPayload(in: connection.outboundBytes())
        #expect(data.bytes.count <= 1)  // only what the 1-octet window allows
        #expect(!data.endStream)  // the rest is deferred until a WINDOW_UPDATE
    }

    @Test("6.9.1/2 — a connection window increment above 2^31-1 is a FLOW_CONTROL_ERROR (§6.9.1)")
    func connectionWindowOverflowIsFlowControlError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .flowControlError,
            feeding: H2Wire.windowUpdate(streamID: 0, increment: 0x7FFF_FFFF),
            on: &connection
        )
    }

    @Test(
        "6.9.1/3 — a stream window increment above 2^31-1 is a stream FLOW_CONTROL_ERROR (§6.9.1)")
    func streamWindowOverflowIsFlowControlError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.windowUpdate(streamID: 1, increment: 0x7FFF_FFFF)
        H2Wire.expectStreamError(.flowControlError, on: 1, feeding: wire, connection: &connection)
    }

    // MARK: §6.9.2 Initial Flow-Control Window Size

    @Test("6.9.2/1 — changing SETTINGS_INITIAL_WINDOW_SIZE adjusts open stream windows (§6.9.2)")
    func changingInitialWindowSizeAdjustsStreams() throws {
        // The peer advertises a 0-octet initial stream window — nothing flows until it opens.
        var connection = try H2Wire.handshaked(clientSettings: [(id: 0x04, value: 0)])
        _ = try connection.receive(H2Wire.get(streamID: 1))
        _ = connection.outboundBytes()
        try connection.respond(
            to: HTTP2StreamID(1),
            HTTPResponse(status: .ok),
            body: Array("hello".utf8)
        )
        #expect(H2Wire.dataPayload(in: connection.outboundBytes()).bytes.isEmpty)  // window 0
        // Opening the initial window releases the deferred body across every open stream.
        _ = try connection.receive(H2Wire.settings([(id: 0x04, value: 5)]))
        #expect(H2Wire.dataPayload(in: connection.outboundBytes()).bytes == Array("hello".utf8))
    }

    @Test(
        "6.9.2/2 — a shrunk SETTINGS_INITIAL_WINDOW_SIZE drives the window negative and is tracked (§6.9.2)"
    )
    func negativeWindowIsTracked() throws {
        // The peer advertises a 5-octet initial stream window.
        var connection = try H2Wire.handshaked(clientSettings: [(id: 0x04, value: 5)])
        _ = try connection.receive(H2Wire.get(streamID: 1))
        _ = connection.outboundBytes()
        try connection.respond(
            to: HTTP2StreamID(1),
            HTTPResponse(status: .ok),
            body: Array("helloworld".utf8)
        )
        _ = connection.outboundBytes()  // "hello" flowed; stream window now 0, "world" deferred
        // Shrinking the initial window to 0 drives the in-flight window negative (0 - 5 = -5).
        _ = try connection.receive(H2Wire.settings([(id: 0x04, value: 0)]))
        #expect(H2Wire.dataPayload(in: connection.outboundBytes()).bytes.isEmpty)
        // A +5 only brings the window back to 0 — still nothing flows (the deficit was tracked).
        _ = try connection.receive(H2Wire.windowUpdate(streamID: 1, increment: 5))
        #expect(H2Wire.dataPayload(in: connection.outboundBytes()).bytes.isEmpty)
        // A further +5 brings it positive; the deferred tail is released.
        _ = try connection.receive(H2Wire.windowUpdate(streamID: 1, increment: 5))
        #expect(H2Wire.dataPayload(in: connection.outboundBytes()).bytes == Array("world".utf8))
    }

    @Test(
        "6.9.2/3 — a SETTINGS_INITIAL_WINDOW_SIZE above the maximum is a FLOW_CONTROL_ERROR (§6.9.2)"
    )
    func oversizedInitialWindowSizeIsFlowControlError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .flowControlError,
            feeding: H2Wire.settings([(id: 0x04, value: 0x8000_0000)]),
            on: &connection
        )
    }

    // MARK: §6.10 CONTINUATION

    @Test("6.10/1 — multiple CONTINUATION frames preceded by a HEADERS frame are accepted (§6.10)")
    func multipleContinuationsAccepted() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(),
            endStream: true,
            endHeaders: false
        )
        wire += H2Wire.continuation(streamID: 1, endHeaders: false)
        wire += H2Wire.continuation(streamID: 1, endHeaders: true)
        H2Wire.expectRequest(wire, on: &connection)
    }

    @Test(
        "6.10/2 — a CONTINUATION followed by a non-CONTINUATION frame is a PROTOCOL_ERROR (§6.10)")
    func continuationThenOtherFrameIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(),
            endStream: false,
            endHeaders: false
        )
        wire += H2Wire.continuation(streamID: 1, endHeaders: false)
        wire += H2Wire.data(streamID: 1, payload: [0x61], endStream: false)
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    @Test("6.10/3 — a CONTINUATION with stream identifier 0x0 is a PROTOCOL_ERROR (§6.10)")
    func continuationOnStreamZeroIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(),
            endStream: false,
            endHeaders: false
        )
        wire += H2Wire.continuation(streamID: 0, endHeaders: true)
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    @Test("6.10/4 — a CONTINUATION after a HEADERS with END_HEADERS is a PROTOCOL_ERROR (§6.10)")
    func continuationAfterEndHeadersIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(),
            endStream: false,
            endHeaders: true
        )
        wire += H2Wire.continuation(streamID: 1, endHeaders: true)
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    @Test(
        "6.10/5 — a CONTINUATION after a CONTINUATION with END_HEADERS is a PROTOCOL_ERROR (§6.10)")
    func continuationAfterContinuationEndHeadersIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(),
            endStream: false,
            endHeaders: false
        )
        wire += H2Wire.continuation(streamID: 1, endHeaders: true)  // completes the block
        wire += H2Wire.continuation(streamID: 1, endHeaders: true)  // extra → illegal
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    @Test("6.10/6 — a CONTINUATION preceded by a DATA frame is a PROTOCOL_ERROR (§6.10)")
    func continuationAfterDataIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)  // HEADERS with END_HEADERS opens the stream
        wire += H2Wire.data(streamID: 1, payload: [0x61], endStream: false)
        wire += H2Wire.continuation(streamID: 1, endHeaders: true)
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    // h2spec coverage: §6.9 (3) + §6.9.1 (3) + §6.9.2 (3) + §6.10 (6) = 15 cases.
}
