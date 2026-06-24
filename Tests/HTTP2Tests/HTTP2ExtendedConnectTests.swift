//
//  HTTP2ExtendedConnectTests.swift
//  HTTP2Tests
//
//  RFC 8441 — the Extended CONNECT tunnel: advertising SETTINGS_ENABLE_CONNECT_PROTOCOL, surfacing an
//  extended CONNECT as a tunnel event, accepting it with a 200, and round-tripping opaque DATA in
//  both directions (the WebSocket-over-HTTP/2 substrate of RFC 9220).
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 8441 — Extended CONNECT tunnel")
struct HTTP2ExtendedConnectTests: HTTP2WireFixtures {
    @Test("the server advertises SETTINGS_ENABLE_CONNECT_PROTOCOL when enabled (§3)")
    func advertisesConnectProtocol() throws {
        var settings = HTTP2Settings()
        settings.enableConnectProtocol = true
        var connection = HTTP2Connection(localSettings: settings)
        var advertised = HTTP2Settings()
        try connection.outboundBytes()
            .withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                let frames = HTTP2FrameDecoder()
                while let frame = try frames.nextFrame(&reader) {
                    guard frame.header.type == .settings else { continue }
                    try frame.payload.withUnsafeBytes { try advertised.apply($0.bytes) }
                }
            }
        #expect(advertised.enableConnectProtocol)
    }

    @Test("an Extended CONNECT opens a tunnel, accepts with 200, and round-trips DATA (§4/§5)")
    func tunnelRoundTrip() throws {
        var settings = HTTP2Settings()
        settings.enableConnectProtocol = true
        var connection = HTTP2Connection(localSettings: settings)
        _ = connection.outboundBytes()  // discard the server preface

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += extendedConnectFrame(streamID: 1, protocol: "websocket")
        let events = try connection.receive(wire)
        _ = connection.outboundBytes()  // discard the SETTINGS ACK

        let event = try #require(events.first)
        guard case .extendedConnect(let streamID, let request, let proto) = event else {
            Issue.record("expected an extendedConnect event")
            return
        }
        #expect(streamID == HTTP2StreamID(1))
        #expect(request.method == .connect)
        #expect(proto == "websocket")

        // Accept → a 200 response with no END_STREAM (the tunnel stays open, §5).
        try connection.acceptTunnel(streamID)
        #expect(try decodeResponse(connection.outboundBytes()).status == "200")

        // Inbound DATA on the tunnel surfaces as opaque tunnel bytes (not a request body).
        let inbound = try connection.receive(
            dataFrame(streamID: 1, payload: Array("client-bytes".utf8), endStream: false))
        guard case .tunnelData(_, let bytes) = try #require(inbound.first) else {
            Issue.record("expected a tunnelData event")
            return
        }
        #expect(bytes == Array("client-bytes".utf8))

        // Server tunnel write becomes a DATA frame, no END_STREAM.
        connection.sendTunnelData(streamID, Array("server-bytes".utf8))
        let out = try collectData(connection.outboundBytes())
        #expect(out.bytes == Array("server-bytes".utf8))
        #expect(!out.endStream)
    }

    @Test("the peer ending a tunnel surfaces tunnelClosed (§5)")
    func tunnelClosedOnEndStream() throws {
        var settings = HTTP2Settings()
        settings.enableConnectProtocol = true
        var connection = HTTP2Connection(localSettings: settings)
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += extendedConnectFrame(streamID: 1, protocol: "websocket")
        _ = try connection.receive(wire)
        try connection.acceptTunnel(HTTP2StreamID(1))

        let events = try connection.receive(dataFrame(streamID: 1, payload: [], endStream: true))
        #expect(events.contains(.tunnelClosed(streamID: HTTP2StreamID(1))))
    }

    @Test("Extended CONNECT without the setting enabled is a stream error (§3)")
    func rejectsWhenDisabled() throws {
        var connection = HTTP2Connection()  // enableConnectProtocol defaults to false
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += extendedConnectFrame(streamID: 1, protocol: "websocket")

        let events = try connection.receive(wire)
        #expect(events.isEmpty)  // refused as a stream error, the connection survives
        let reset = try firstRstStream(connection.outboundBytes())
        #expect(reset?.code == .protocolError)
    }

    /// The first RST_STREAM frame on the wire (its decoded error code), if any.
    private func firstRstStream(
        _ bytes: [UInt8]
    ) throws -> (streamID: HTTP2StreamID, code: HTTP2ErrorCode)? {
        var found: (HTTP2StreamID, HTTP2ErrorCode)?
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while found == nil, let frame = try frames.nextFrame(&reader) {
                guard frame.header.type == .rstStream, frame.payload.count == 4 else { continue }
                let code =
                    UInt32(frame.payload[0]) << 24 | UInt32(frame.payload[1]) << 16
                    | UInt32(frame.payload[2]) << 8 | UInt32(frame.payload[3])
                found = (frame.header.streamID, HTTP2ErrorCode(code: code))
            }
        }
        guard let found else { return nil }
        return (streamID: found.0, code: found.1)
    }
}
