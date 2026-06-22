//
//  HTTP2ConnectionTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for the RFC 9113 sans-I/O connection engine: the preface + SETTINGS handshake,
//  decoding a GET and a POST-with-body into request events, fragmented delivery, and the bad-preface
//  rejection.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 — connection engine")
struct HTTP2ConnectionTests {

    // MARK: Wire builders

    private func settingsFrame() -> [UInt8] {
        var out = [UInt8]()
        HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection).encode(
            into: &out)
        return out
    }

    private func headersFrame(streamID: UInt32, fields: [HPACKField], endStream: Bool) -> [UInt8] {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4096)
        let block = encoder.encode(fields)
        var flags: HTTP2FrameFlags = [.endHeaders]
        if endStream { flags.insert(.endStream) }
        var out = [UInt8]()
        HTTP2FrameHeader(
            payloadLength: block.count, type: .headers, flags: flags,
            streamID: HTTP2StreamID(streamID)
        ).encode(into: &out)
        out.append(contentsOf: block)
        return out
    }

    private func dataFrame(streamID: UInt32, payload: [UInt8], endStream: Bool) -> [UInt8] {
        var out = [UInt8]()
        HTTP2FrameHeader(
            payloadLength: payload.count, type: .data, flags: endStream ? [.endStream] : [],
            streamID: HTTP2StreamID(streamID)
        ).encode(into: &out)
        out.append(contentsOf: payload)
        return out
    }

    private func get(streamID: UInt32, path: String) -> [UInt8] {
        headersFrame(
            streamID: streamID,
            fields: [
                HPACKField(name: ":method", value: "GET"),
                HPACKField(name: ":scheme", value: "https"),
                HPACKField(name: ":path", value: path),
                HPACKField(name: ":authority", value: "example.com"),
            ], endStream: true)
    }

    /// A HEADERS frame that opens a stream without END_STREAM (a body is still expected).
    private func openStream(streamID: UInt32) -> [UInt8] {
        headersFrame(
            streamID: streamID,
            fields: [
                HPACKField(name: ":method", value: "POST"),
                HPACKField(name: ":scheme", value: "https"),
                HPACKField(name: ":path", value: "/"),
                HPACKField(name: ":authority", value: "example.com"),
            ], endStream: false)
    }

    private func rstStreamFrame(streamID: UInt32, code: UInt32 = 8) -> [UInt8] {
        var out = [UInt8]()
        HTTP2FrameHeader(payloadLength: 4, type: .rstStream, streamID: HTTP2StreamID(streamID))
            .encode(into: &out)
        out.append(contentsOf: [
            UInt8((code >> 24) & 0xFF), UInt8((code >> 16) & 0xFF),
            UInt8((code >> 8) & 0xFF), UInt8(code & 0xFF),
        ])
        return out
    }

    // MARK: Handshake + request decoding

    @Test("performs the handshake and decodes a GET request")
    func decodesGetRequest() throws {
        var connection = HTTP2Connection()
        #expect(!connection.outboundBytes().isEmpty)  // server SETTINGS preface queued at init

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 1, path: "/index.html")

        let events = try connection.receive(wire)
        #expect(events.count == 1)
        let event = try #require(events.first)
        guard case .request(let streamID, let request, let body) = event else {
            Issue.record("expected a request event")
            return
        }
        #expect(streamID == HTTP2StreamID(1))
        #expect(request.method == .get)
        #expect(request.scheme == "https")
        #expect(request.path == "/index.html")
        #expect(request.authority == "example.com")
        #expect(body.isEmpty)
        #expect(!connection.outboundBytes().isEmpty)  // SETTINGS ACK queued
    }

    @Test("decodes a POST request with a DATA body")
    func decodesPostWithBody() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += headersFrame(
            streamID: 1,
            fields: [
                HPACKField(name: ":method", value: "POST"),
                HPACKField(name: ":scheme", value: "https"),
                HPACKField(name: ":path", value: "/submit"),
                HPACKField(name: ":authority", value: "example.com"),
            ], endStream: false)
        wire += dataFrame(streamID: 1, payload: Array("hello world".utf8), endStream: true)

        let events = try connection.receive(wire)
        let event = try #require(events.first)
        guard case .request(_, let request, let body) = event else {
            Issue.record("expected a request event")
            return
        }
        #expect(request.method == .post)
        #expect(String(decoding: body, as: UTF8.self) == "hello world")
    }

    @Test("assembles a request delivered across two reads")
    func fragmentedDelivery() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 1, path: "/")

        let split = wire.count / 2
        #expect(try connection.receive(wire[..<split]).isEmpty)  // partial — nothing yet
        let events = try connection.receive(wire[split...])
        #expect(events.count == 1)
    }

    @Test("two requests on increasing stream identifiers both decode")
    func twoStreams() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 1, path: "/a")
        wire += get(streamID: 3, path: "/b")

        let events = try connection.receive(wire)
        #expect(events.count == 2)
    }

    @Test("the server preface advertises ENABLE_PUSH = 0 (RFC 9113 §6.5.2)")
    func serverDisablesPush() throws {
        var connection = HTTP2Connection()
        let preface = connection.outboundBytes()
        var settings = HTTP2Settings()  // ENABLE_PUSH defaults to 1; the server frame must clear it
        try preface.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) {
                if frame.header.type == .settings {
                    try frame.payload.withUnsafeBytes { try settings.apply($0.bytes) }
                }
            }
        }
        #expect(settings.enablePush == false)
    }

    // MARK: Failure modes

    @Test("a bad client preface is a PROTOCOL_ERROR")
    func badPreface() {
        var connection = HTTP2Connection()
        var bad = HTTP2ConnectionPreface.client
        bad[0] = 0x47  // 'G'
        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(bad)
        } catch {
            thrown = error.code  // `receive` uses typed throws, so `error` is already an HTTP2Error
        }
        #expect(thrown == .protocolError)
    }

    @Test("a non-increasing stream identifier is a PROTOCOL_ERROR (§5.1.1)")
    func decreasingStreamID() {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 3, path: "/a")
        wire += get(streamID: 1, path: "/b")  // lower than 3 — illegal

        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(wire)
        } catch {
            thrown = error.code  // `receive` uses typed throws, so `error` is already an HTTP2Error
        }
        #expect(thrown == .protocolError)
    }

    @Test("excessive stream resets trigger ENHANCE_YOUR_CALM (Rapid Reset, CVE-2023-44487)")
    func rapidReset() {
        var connection = HTTP2Connection(limits: HTTPLimits(maxStreamResetsPerInterval: 5))
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        var streamID: UInt32 = 1
        for _ in 0..<10 {  // open a stream then immediately reset it, ten times
            wire += openStream(streamID: streamID)
            wire += rstStreamFrame(streamID: streamID)
            streamID += 2
        }
        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(wire)
        } catch {
            thrown = error.code  // `receive` uses typed throws, so `error` is already an HTTP2Error
        }
        #expect(thrown == .enhanceYourCalm)
    }

    @Test("refuses streams beyond SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 §5.1.2)")
    func refusesExcessConcurrentStreams() throws {
        var connection = HTTP2Connection(limits: HTTPLimits(maxConcurrentStreams: 2))
        _ = connection.outboundBytes()  // discard the server SETTINGS preface
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += openStream(streamID: 1)  // opens (no END_STREAM, stays active)
        wire += openStream(streamID: 3)  // opens — now at the cap of 2
        wire += openStream(streamID: 5)  // exceeds the cap — must be refused, not fatal

        let events = try connection.receive(wire)
        #expect(events.isEmpty)  // none completed; the 3rd is refused, the connection survives
        // The server queued RST_STREAM(REFUSED_STREAM) for the excess stream.
        let refused = try firstRstStream(connection.outboundBytes())
        #expect(refused?.streamID == HTTP2StreamID(5))
        #expect(refused?.code == .refusedStream)
    }

    // MARK: Response encoding

    @Test("encodes a response (HEADERS + DATA) for a received request")
    func encodesResponse() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()  // discard the server SETTINGS preface

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 1, path: "/")
        let events = try connection.receive(wire)
        _ = connection.outboundBytes()  // discard the SETTINGS ACK

        let event = try #require(events.first)
        guard case .request(let streamID, _, _) = event else {
            Issue.record("expected a request event")
            return
        }

        var response = HTTPResponse(status: .ok)
        _ = response.headerFields.append("text/plain", for: .contentType)
        try connection.respond(to: streamID, response, body: Array("hello".utf8))

        let decoded = try decodeResponse(connection.outboundBytes())
        #expect(decoded.status == "200")
        #expect(decoded.contentType == "text/plain")
        #expect(String(decoding: decoded.body, as: UTF8.self) == "hello")
    }

    /// Parses a response off the wire: HPACK-decodes the HEADERS block and concatenates DATA.
    private func decodeResponse(
        _ bytes: [UInt8]
    ) throws -> (status: String?, contentType: String?, body: [UInt8]) {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4096)
        var status: String?
        var contentType: String?
        var body = [UInt8]()
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) {
                switch frame.header.type {
                case .headers:
                    let fragment = try HTTP2HeadersFrame.fieldBlockFragment(
                        frame.payload, flags: frame.header.flags)
                    let fields = try Array(fragment).withUnsafeBytes {
                        try decoder.decode($0.bytes)
                    }
                    for field in fields where field.name == ":status" { status = field.value }
                    for field in fields where field.name == "content-type" {
                        contentType = field.value
                    }
                case .data:
                    body.append(contentsOf: frame.payload)
                default:
                    break
                }
            }
        }
        return (status, contentType, body)
    }

    /// The first RST_STREAM frame on the wire (its stream id and decoded error code), if any.
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
