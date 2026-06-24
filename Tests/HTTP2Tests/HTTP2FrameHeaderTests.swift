//
//  HTTP2FrameHeaderTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for the RFC 9113 §4.1 frame header: the 24-bit length, type/flags octets, the
//  31-bit stream identifier with its reserved bit masked, round-trip, and short-buffer handling.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 §4.1 — frame header")
struct HTTP2FrameHeaderTests {
    private func parse(_ bytes: [UInt8]) -> HTTP2FrameHeader? {
        bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            return HTTP2FrameHeader.parse(&reader)
        }
    }

    private func encode(_ header: HTTP2FrameHeader) -> [UInt8] {
        var output: [UInt8] = []
        header.encode(into: &output)
        return output
    }

    @Test("parses a SETTINGS frame header (length 18, stream 0)")
    func parsesSettings() {
        let header = parse([0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        #expect(header?.payloadLength == 18)
        #expect(header?.type == .settings)
        #expect(header?.flags.isEmpty == true)
        #expect(header?.streamID == .connection)
    }

    @Test("parses a SETTINGS ACK (length 0, ACK flag)")
    func parsesSettingsAck() {
        let header = parse([0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00])
        #expect(header?.payloadLength == 0)
        #expect(header?.type == .settings)
        #expect(header?.flags.contains(.ack) == true)
    }

    @Test("parses a HEADERS frame on stream 1 with END_STREAM | END_HEADERS")
    func parsesHeaders() {
        let header = parse([0x00, 0x00, 0x04, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01])
        #expect(header?.type == .headers)
        #expect(header?.payloadLength == 4)
        #expect(header?.flags == [.endStream, .endHeaders])
        #expect(header?.streamID == HTTP2StreamID(1))
        #expect(header?.streamID.isClientInitiated == true)
    }

    @Test("ignores the reserved high bit of the stream identifier (§4.1)")
    func masksReservedBit() {
        // 0x80 00 00 01 in the stream field → stream 1 once the reserved bit is masked.
        let header = parse([0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00, 0x00, 0x01])
        #expect(header?.streamID == HTTP2StreamID(1))
    }

    @Test("reads the full 24-bit maximum length")
    func parsesMaxLength() {
        let header = parse([0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        #expect(header?.payloadLength == 0xFF_FFFF)  // 16,777,215
    }

    @Test("round-trips through encode then parse")
    func roundTrips() {
        let original = HTTP2FrameHeader(
            payloadLength: 1_337,
            type: .data,
            flags: [.endStream, .padded],
            streamID: HTTP2StreamID(42)
        )
        #expect(parse(encode(original)) == original)
        #expect(encode(original).count == HTTP2FrameHeader.encodedLength)
    }

    @Test("returns nil when fewer than nine octets are available")
    func shortBuffer() {
        #expect(parse([0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00]) == nil)
        #expect(parse([]) == nil)
    }
}
