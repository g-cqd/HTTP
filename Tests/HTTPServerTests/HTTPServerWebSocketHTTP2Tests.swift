//
//  HTTPServerWebSocketHTTP2Tests.swift
//  HTTPServerTests
//
//  Drives WebSocket-over-HTTP/2 (RFC 8441 / RFC 9220) end-to-end over an in-memory FakeConnection: an
//  HTTP/2 Extended CONNECT (`:protocol = websocket`) plus a masked WebSocket text frame in a DATA
//  frame go in; a `:status = 200` and the echoed frame as DATA on the same stream must come back.
//

import HPACK
import HTTP2
import HTTPCore
import HTTPTransport
import Testing
import WebSocket

@testable import HTTPServer

@Suite("HTTPServer — WebSocket over HTTP/2 (RFC 8441)")
struct HTTPServerWebSocketHTTP2Tests {

    @Test("Extended CONNECT upgrades to WebSocket and echoes a text frame")
    func webSocketOverHTTP2() async throws {
        let echo = ClosureWebSocketHandler { event in
            guard case .message(let opcode, let payload) = event, opcode == .text else { return [] }
            return [.sendText(String(decoding: payload, as: UTF8.self))]
        }

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += extendedConnect(streamID: 1)
        wire += dataFrame(streamID: 1, payload: maskedText("hi"))  // the client's first WS frame

        let connection = FakeConnection(id: TransportConnectionID(1), inbound: wire)
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: ClosureResponder { _, _ in ServerResponse(HTTPResponse(status: .notFound)) },
            webSocketHandler: echo)
        await server.serve(connection)

        let frames = try decodeFrames(await connection.sentBytes())
        #expect(try status(ofStream: 1, in: frames) == "200")  // tunnel accepted (§5)
        // The echoed WebSocket frame rides a DATA frame on stream 1: unmasked text "hi".
        let tunnelBytes =
            frames
            .filter { $0.header.type == .data && $0.header.streamID == HTTP2StreamID(1) }
            .flatMap(\.payload)
        #expect(containsSubsequence(tunnelBytes, [0x81, 0x02, 0x68, 0x69]))
    }

    // MARK: Wire builders

    private func settingsFrame() -> [UInt8] {
        var out = [UInt8]()
        HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection).encode(
            into: &out)
        return out
    }

    private func extendedConnect(streamID: UInt32) -> [UInt8] {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4096)
        let block = encoder.encode([
            HPACKField(name: ":method", value: "CONNECT"),
            HPACKField(name: ":protocol", value: "websocket"),
            HPACKField(name: ":scheme", value: "https"),
            HPACKField(name: ":path", value: "/chat"),
            HPACKField(name: ":authority", value: "example.com"),
        ])
        var out = [UInt8]()
        HTTP2FrameHeader(
            payloadLength: block.count, type: .headers, flags: [.endHeaders],
            streamID: HTTP2StreamID(streamID)
        ).encode(into: &out)
        out += block
        return out
    }

    private func dataFrame(streamID: UInt32, payload: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        HTTP2FrameHeader(
            payloadLength: payload.count, type: .data, streamID: HTTP2StreamID(streamID)
        )
        .encode(into: &out)
        out += payload
        return out
    }

    private func maskedText(_ text: String) -> [UInt8] {
        let payload = Array(text.utf8)
        let key: [UInt8] = [0x11, 0x22, 0x33, 0x44]
        var frame: [UInt8] = [0x81, 0x80 | UInt8(payload.count)]
        frame += key
        for (index, byte) in payload.enumerated() { frame.append(byte ^ key[index & 0x3]) }
        return frame
    }

    // MARK: Wire parsers

    private func decodeFrames(_ bytes: [UInt8]) throws -> [HTTP2FrameDecoder.Frame] {
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            var decoded = [HTTP2FrameDecoder.Frame]()
            while let frame = try frames.nextFrame(&reader) { decoded.append(frame) }
            return decoded
        }
    }

    private func status(
        ofStream streamID: UInt32, in frames: [HTTP2FrameDecoder.Frame]
    ) throws
        -> String?
    {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4096)
        var status: String?
        for frame in frames where frame.header.type == .headers {
            let fragment = try HTTP2HeadersFrame.fieldBlockFragment(
                frame.payload, flags: frame.header.flags)
            let fields = try Array(fragment).withUnsafeBytes { try decoder.decode($0.bytes) }
            guard frame.header.streamID == HTTP2StreamID(streamID) else { continue }
            for field in fields where field.name == ":status" { status = field.value }
        }
        return status
    }

    private func containsSubsequence(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard needle.count <= haystack.count, !needle.isEmpty else { return false }
        for start in 0...(haystack.count - needle.count)
        where Array(haystack[start..<start + needle.count]) == needle {
            return true
        }
        return false
    }
}
