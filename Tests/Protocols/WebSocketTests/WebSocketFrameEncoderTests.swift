//
//  WebSocketFrameEncoderTests.swift
//  WebSocketTests
//
//  RFC 6455 §5.2 — the frame encoder, and the `decode ∘ encode == id` round-trip across the three
//  payload-length forms (7/16/64-bit) that proves the codec self-consistent.
//

import HTTPCore
import Testing

@testable import WebSocket

@Suite("RFC 6455 §5.2 — frame encoder")
struct WebSocketFrameEncoderTests {
    @Test("a server frame is emitted unmasked (RFC 6455 §5.1)")
    func serverFramesAreUnmasked() {
        let wire = WebSocketFrameEncoder()
            .encode(
                WebSocketFrame(opcode: .text, payload: Array("hi".utf8))
            )
        #expect(wire[0] == 0x81)  // FIN | text
        #expect(wire[1] & 0x80 == 0)  // MASK bit clear
        #expect(wire[1] == 0x02)  // length 2
    }

    @Test(
        "encode then decode reproduces the frame across the 7/16/64-bit length forms",
        arguments: [0, 1, 125, 126, 200, 0xFFFF, 0x1_0000])
    func roundTrips(payloadLength: Int) throws {
        let frame = WebSocketFrame(
            opcode: .binary,
            payload: (0 ..< payloadLength).map { UInt8($0 & 0xFF) }
        )
        let wire = WebSocketFrameEncoder().encode(frame)

        let decoded = try wire.withUnsafeBytes { raw -> WebSocketFrame? in
            var reader = ByteReader(raw)
            return try WebSocketFrameDecoder(maxPayloadLength: 1 << 20).nextFrame(&reader)
        }
        #expect(decoded == frame)
    }

    @Test("a non-final continuation frame keeps its FIN bit clear (RFC 6455 §5.4)")
    func preservesFragmentation() throws {
        let frame = WebSocketFrame(isFinal: false, opcode: .text, payload: Array("part".utf8))
        let wire = WebSocketFrameEncoder().encode(frame)
        #expect(wire[0] & 0x80 == 0)  // FIN clear
        let decoded = try wire.withUnsafeBytes { raw -> WebSocketFrame? in
            var reader = ByteReader(raw)
            return try WebSocketFrameDecoder().nextFrame(&reader)
        }
        #expect(decoded?.isFinal == false)
    }
}
