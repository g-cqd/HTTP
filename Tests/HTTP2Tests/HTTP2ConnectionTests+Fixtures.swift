//
//  HTTP2ConnectionTests+Fixtures.swift
//  HTTP2Tests
//
//  Wire-frame builders shared by the connection-engine tests: small helpers that assemble RFC 9113
//  frames (SETTINGS, HEADERS via HPACK, DATA, WINDOW_UPDATE, RST_STREAM, PING) for the fixtures.
//

import HPACK
import HTTPCore

@testable import HTTP2

/// Wire-frame builders + parsers shared by the HTTP/2 connection-engine test suites.
protocol HTTP2WireFixtures {}

extension HTTP2ConnectionTests: HTTP2WireFixtures {}

extension HTTP2WireFixtures {
    func settingsFrame() -> [UInt8] {
        var out: [UInt8] = []
        HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection)
            .encode(
                into: &out)
        return out
    }

    func headersFrame(streamID: UInt32, fields: [HPACKField], endStream: Bool) -> [UInt8] {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = encoder.encode(fields)
        var flags: HTTP2FrameFlags = [.endHeaders]
        if endStream { flags.insert(.endStream) }
        var out: [UInt8] = []
        HTTP2FrameHeader(
            payloadLength: block.count, type: .headers, flags: flags,
            streamID: HTTP2StreamID(streamID)
        )
        .encode(into: &out)
        out.append(contentsOf: block)
        return out
    }

    /// A HEADERS frame carrying the deprecated priority section (RFC 9113 §6.2) whose 31-bit stream
    /// dependency points at its own `streamID` — the self-dependency rejected by §5.3.1.
    func selfDependentHeadersFrame(streamID: UInt32) -> [UInt8] {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = encoder.encode([
            HPACKField(name: ":method", value: "GET"),
            HPACKField(name: ":scheme", value: "https"),
            HPACKField(name: ":path", value: "/"),
            HPACKField(name: ":authority", value: "example.com")
        ])
        let priority: [UInt8] = [  // E=0, 31-bit dependency = streamID, weight = 0
            UInt8((streamID >> 24) & 0xFF), UInt8((streamID >> 16) & 0xFF),
            UInt8((streamID >> 8) & 0xFF), UInt8(streamID & 0xFF), 0x00
        ]
        var out: [UInt8] = []
        HTTP2FrameHeader(
            payloadLength: priority.count + block.count, type: .headers,
            flags: [.endHeaders, .endStream, .priority], streamID: HTTP2StreamID(streamID)
        )
        .encode(into: &out)
        out.append(contentsOf: priority)
        out.append(contentsOf: block)
        return out
    }

    func dataFrame(streamID: UInt32, payload: [UInt8], endStream: Bool) -> [UInt8] {
        var out: [UInt8] = []
        HTTP2FrameHeader(
            payloadLength: payload.count, type: .data, flags: endStream ? [.endStream] : [],
            streamID: HTTP2StreamID(streamID)
        )
        .encode(into: &out)
        out.append(contentsOf: payload)
        return out
    }

    func get(streamID: UInt32, path: String) -> [UInt8] {
        headersFrame(
            streamID: streamID,
            fields: [
                HPACKField(name: ":method", value: "GET"),
                HPACKField(name: ":scheme", value: "https"),
                HPACKField(name: ":path", value: path),
                HPACKField(name: ":authority", value: "example.com")
            ], endStream: true)
    }

    /// A HEADERS frame that opens a stream without END_STREAM (a body is still expected).
    func openStream(streamID: UInt32) -> [UInt8] {
        headersFrame(
            streamID: streamID,
            fields: [
                HPACKField(name: ":method", value: "POST"),
                HPACKField(name: ":scheme", value: "https"),
                HPACKField(name: ":path", value: "/"),
                HPACKField(name: ":authority", value: "example.com")
            ], endStream: false)
    }

    /// An Extended CONNECT HEADERS frame (RFC 8441 §4) opening a tunnel for `protocol`, no END_STREAM.
    func extendedConnectFrame(streamID: UInt32, protocol proto: String) -> [UInt8] {
        headersFrame(
            streamID: streamID,
            fields: [
                HPACKField(name: ":method", value: "CONNECT"),
                HPACKField(name: ":protocol", value: proto),
                HPACKField(name: ":scheme", value: "https"),
                HPACKField(name: ":path", value: "/chat"),
                HPACKField(name: ":authority", value: "example.com")
            ], endStream: false)
    }

    func rstStreamFrame(streamID: UInt32, code: UInt32 = 8) -> [UInt8] {
        var out: [UInt8] = []
        HTTP2FrameHeader(payloadLength: 4, type: .rstStream, streamID: HTTP2StreamID(streamID))
            .encode(into: &out)
        out.append(contentsOf: [
            UInt8((code >> 24) & 0xFF), UInt8((code >> 16) & 0xFF),
            UInt8((code >> 8) & 0xFF), UInt8(code & 0xFF)
        ])
        return out
    }

    /// A SETTINGS frame advertising a single parameter: the peer's initial stream window (§6.5.2).
    func settingsFrame(initialWindowSize: UInt32) -> [UInt8] {
        var out: [UInt8] = []
        let payload: [UInt8] = [
            0x00, 0x04,  // SETTINGS_INITIAL_WINDOW_SIZE
            UInt8((initialWindowSize >> 24) & 0xFF), UInt8((initialWindowSize >> 16) & 0xFF),
            UInt8((initialWindowSize >> 8) & 0xFF), UInt8(initialWindowSize & 0xFF)
        ]
        HTTP2FrameHeader(payloadLength: payload.count, type: .settings, streamID: .connection)
            .encode(into: &out)
        out.append(contentsOf: payload)
        return out
    }

    func windowUpdateFrame(streamID: UInt32, increment: UInt32) -> [UInt8] {
        var out: [UInt8] = []
        HTTP2FrameHeader(payloadLength: 4, type: .windowUpdate, streamID: HTTP2StreamID(streamID))
            .encode(into: &out)
        out.append(contentsOf: [
            UInt8((increment >> 24) & 0xFF), UInt8((increment >> 16) & 0xFF),
            UInt8((increment >> 8) & 0xFF), UInt8(increment & 0xFF)
        ])
        return out
    }

    func pingFrame() -> [UInt8] {
        var out: [UInt8] = []
        HTTP2FrameHeader(payloadLength: 8, type: .ping, streamID: .connection).encode(into: &out)
        out.append(contentsOf: [UInt8](repeating: 0, count: 8))
        return out
    }

    /// Parses a response off the wire: HPACK-decodes the HEADERS block and concatenates DATA.
    func decodeResponse(
        _ bytes: [UInt8]
    ) throws -> (status: String?, contentType: String?, body: [UInt8]) {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        var status: String?
        var contentType: String?
        var body: [UInt8] = []
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) {
                switch frame.header.type {
                    case .headers:
                        let fragment = try HTTP2HeadersFrame.fieldBlockFragment(
                            frame.payload, flags: frame.header.flags)
                        let fields = try Array(fragment)
                            .withUnsafeBytes {
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
    /// Concatenates every DATA-frame payload on the wire, reporting whether any carried END_STREAM.
    func collectData(_ bytes: [UInt8]) throws -> (bytes: [UInt8], endStream: Bool) {
        var data: [UInt8] = []
        var endStream = false
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) {
                guard frame.header.type == .data else { continue }
                data.append(contentsOf: frame.payload)
                if frame.header.flags.contains(.endStream) { endStream = true }
            }
        }
        return (data, endStream)
    }
    /// Sums the increment of every WINDOW_UPDATE frame on the wire.
    func sumWindowUpdates(_ bytes: [UInt8]) throws -> Int {
        var total = 0
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) {
                guard frame.header.type == .windowUpdate, frame.payload.count == 4 else { continue }
                let increment =
                    UInt32(frame.payload[0]) << 24 | UInt32(frame.payload[1]) << 16
                    | UInt32(frame.payload[2]) << 8 | UInt32(frame.payload[3])
                total += Int(increment & 0x7FFF_FFFF)
            }
        }
        return total
    }
}
