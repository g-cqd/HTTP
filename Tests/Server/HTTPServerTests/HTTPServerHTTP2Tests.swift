//
//  HTTPServerHTTP2Tests.swift
//  HTTPServerTests
//
//  Drives the server's HTTP/2 (h2c prior-knowledge) path over an in-memory FakeConnection: a client
//  preface + SETTINGS + HEADERS goes in, and a decoded response (:status + body) must come back —
//  proving the protocol sniff and the HTTP2Connection driver without a socket.
//

import HPACK
import HTTP2
import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — HTTP/2 (h2c) dispatch")
struct HTTPServerHTTP2Tests {
    @Test("serves an HTTP/2 prior-knowledge request end-to-end")
    func servesHTTP2Request() async throws {
        let responder = ClosureResponder { request, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array("h2 from \(request.path)".utf8))
        }

        var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = encoder.encode([
            HPACKField(name: ":method", value: "GET"),
            HPACKField(name: ":scheme", value: "http"),
            HPACKField(name: ":path", value: "/hi"),
            HPACKField(name: ":authority", value: "x")
        ])
        var wire = HTTP2ConnectionPreface.client
        var settings: [UInt8] = []
        HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection)
            .encode(into: &settings)
        wire += settings
        HTTP2FrameHeader(
            payloadLength: block.count,
            type: .headers,
            flags: [.endHeaders, .endStream],
            streamID: HTTP2StreamID(1)
        )
        .encode(into: &wire)
        wire += block

        let connection = FakeConnection(id: TransportConnectionID(1), inbound: wire)
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)

        let response = try decodeHTTP2Response(await connection.sentBytes())
        #expect(response.status == "200")
        #expect(String(decoding: response.body, as: Unicode.UTF8.self) == "h2 from /hi")
    }

    @Test("an HTTP/2 streaming route receives its body as a stream (Phase 1.4)")
    func servesHTTP2StreamingRoute() async throws {
        let router = Router {
            Route.post("/upload") { _, body, _ in
                .text("streaming=\(body.isStreaming) bytes=\(await body.collect().count)")
            }
            .streamingBody()
        }
        var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = encoder.encode([
            HPACKField(name: ":method", value: "POST"),
            HPACKField(name: ":scheme", value: "http"),
            HPACKField(name: ":path", value: "/upload"),
            HPACKField(name: ":authority", value: "x")
        ])
        var wire = HTTP2ConnectionPreface.client
        var settings: [UInt8] = []
        HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection)
            .encode(into: &settings)
        wire += settings
        // HEADERS without END_STREAM — a DATA frame follows.
        HTTP2FrameHeader(
            payloadLength: block.count,
            type: .headers,
            flags: [.endHeaders],
            streamID: HTTP2StreamID(1)
        )
        .encode(into: &wire)
        wire += block
        let body = Array("hello".utf8)
        HTTP2FrameHeader(
            payloadLength: body.count,
            type: .data,
            flags: [.endStream],
            streamID: HTTP2StreamID(1)
        )
        .encode(into: &wire)
        wire += body

        let connection = FakeConnection(id: TransportConnectionID(1), inbound: wire)
        let server = HTTPServer(transport: FakeTransport(), responder: router)
        await server.serve(connection)

        let response = try decodeHTTP2Response(await connection.sentBytes())
        #expect(response.status == "200")
        #expect(String(decoding: response.body, as: Unicode.UTF8.self) == "streaming=true bytes=5")
    }

    @Test("an ALPN-negotiated h2 connection is driven by the engine, not the preface sniffer")
    func alpnCommitsToHTTP2() async throws {
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        // First octets that are NOT the client preface: a sniffing server would mis-route this to
        // HTTP/1.1, but ALPN "h2" commits the connection to HTTP/2 (RFC 9113 §3.3), so the engine
        // answers with a GOAWAY (PROTOCOL_ERROR) — never an HTTP/1 status line.
        let connection = FakeConnection(
            id: TransportConnectionID(1),
            negotiatedApplicationProtocol: "h2",
            inbound: Array("INVALID CONNECTION PREFACE\r\n\r\n".utf8)
        )
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)

        let out = await connection.sentBytes()
        #expect(out.first != UInt8(ascii: "H"))  // not an "HTTP/1.1 ..." status line
        #expect(try http2FrameTypes(out).contains(.goAway))
    }

    @Test("a draining server sends GOAWAY after answering the in-flight request (RFC 9113 §6.8)")
    func http2DrainsWithGoAway() async throws {
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = encoder.encode([
            HPACKField(name: ":method", value: "GET"),
            HPACKField(name: ":scheme", value: "http"),
            HPACKField(name: ":path", value: "/hi"),
            HPACKField(name: ":authority", value: "x")
        ])
        var wire = HTTP2ConnectionPreface.client
        var settings: [UInt8] = []
        HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection)
            .encode(into: &settings)
        wire += settings
        HTTP2FrameHeader(
            payloadLength: block.count,
            type: .headers,
            flags: [.endHeaders, .endStream],
            streamID: HTTP2StreamID(1)
        )
        .encode(into: &wire)
        wire += block

        let connection = FakeConnection(id: TransportConnectionID(1), inbound: wire)
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.shutdown()  // begin draining before this connection is served
        await server.serve(connection)

        #expect(try http2FrameTypes(await connection.sentBytes()).contains(.goAway))
    }

    /// The frame types present on the wire, in order (used to assert h2 framing in responses).
    private func http2FrameTypes(_ bytes: [UInt8]) throws -> [HTTP2FrameType] {
        var types: [HTTP2FrameType] = []
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) { types.append(frame.header.type) }
        }
        return types
    }

    private func decodeHTTP2Response(_ bytes: [UInt8]) throws -> (status: String?, body: [UInt8]) {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        var status: String?
        var body: [UInt8] = []
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) {
                switch frame.header.type {
                    case .headers:
                        let fragment = try HTTP2HeadersFrame.fieldBlockFragment(
                            frame.payload, flags: frame.header.flags
                        )
                        let fields = try Array(fragment)
                            .withUnsafeBytes {
                                try decoder.decode($0.bytes)
                            }
                        for field in fields where field.name == ":status" { status = field.value }
                    case .data:
                        body.append(contentsOf: frame.payload)
                    default:
                        break
                }
            }
        }
        return (status, body)
    }
}
