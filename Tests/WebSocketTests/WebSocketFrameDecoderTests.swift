//
//  WebSocketFrameDecoderTests.swift
//  WebSocketTests
//
//  RED→GREEN driver for the RFC 6455 §5.2 frame decoder: unmasked and masked data frames, the
//  7/16/64-bit length forms, incremental delivery, and the §5.2/§5.5 framing violations.
//

import HTTPCore
import Testing

@testable import WebSocket

@Suite("RFC 6455 §5.2 — frame decoder")
struct WebSocketFrameDecoderTests {

    // MARK: Decoding

    @Test("decodes an unmasked text frame")
    func decodesUnmaskedTextFrame() throws {
        let frame = try firstFrame([0x81, 0x02, 0x48, 0x69])  // FIN|text, len 2, "Hi"
        #expect(frame?.isFinal == true)
        #expect(frame?.opcode == .text)
        #expect(frame?.payload == Array("Hi".utf8))
    }

    @Test("unmasks a masked client frame (RFC 6455 §5.3)")
    func unmasksMaskedFrame() throws {
        let frame = try firstFrame(maskedFrame(opcode: .binary, payload: Array("payload".utf8)))
        #expect(frame?.opcode == .binary)
        #expect(frame?.payload == Array("payload".utf8))
    }

    @Test("decodes a 16-bit extended length (RFC 6455 §5.2)")
    func decodesExtended16BitLength() throws {
        let body = [UInt8](repeating: 0x7a, count: 200)
        var wire: [UInt8] = [0x82, 126, 0x00, 200]  // FIN|binary, len==126, 200 in 2 octets
        wire += body
        let frame = try firstFrame(wire)
        #expect(frame?.payload.count == 200)
    }

    @Test("decodes two concatenated frames in sequence")
    func decodesTwoFrames() throws {
        var wire: [UInt8] = [0x81, 0x01, 0x41]  // "A"
        wire += [0x81, 0x01, 0x42]  // "B"
        let frames = try allFrames(wire)
        #expect(frames.map(\.payload) == [Array("A".utf8), Array("B".utf8)])
    }

    // MARK: Incremental delivery

    @Test("an incomplete header yields nil without consuming")
    func partialHeaderReturnsNil() throws {
        #expect(try firstFrame([0x81]) == nil)  // opcode byte only
    }

    @Test("a header without its full payload yields nil")
    func partialPayloadReturnsNil() throws {
        #expect(try firstFrame([0x81, 0x05, 0x48, 0x69]) == nil)  // declares 5, supplies 2
    }

    // MARK: Framing violations (RFC 6455 §5.2 / §5.5)

    @Test("a set reserved bit is rejected (§5.2)")
    func reservedBitsRejected() {
        #expect(throws: WebSocketError.reservedBitsSet) { try firstFrame([0xC1, 0x00]) }  // RSV1
    }

    @Test("a reserved opcode is rejected (§5.2)")
    func reservedOpcodeRejected() {
        #expect(throws: WebSocketError.reservedOpcode(0x3)) { try firstFrame([0x83, 0x00]) }
    }

    @Test("a fragmented control frame is rejected (§5.5)")
    func fragmentedControlRejected() {
        #expect(throws: WebSocketError.fragmentedControlFrame) {
            try firstFrame([0x08, 0x00])  // FIN clear, opcode close
        }
    }

    @Test("a control frame longer than 125 octets is rejected (§5.5)")
    func oversizedControlRejected() {
        #expect(throws: WebSocketError.controlFrameTooLong) {
            try firstFrame([0x89, 126, 0x00, 200])  // FIN|ping, len==126
        }
    }

    @Test("a payload past the configured maximum is rejected")
    func payloadTooLongRejected() {
        var wire: [UInt8] = [0x82, 126, 0x00, 200]
        wire += [UInt8](repeating: 0, count: 200)
        #expect(throws: WebSocketError.payloadTooLong) {
            try firstFrame(wire, maxPayloadLength: 64)
        }
    }

    @Test("a non-minimal 16-bit length is rejected (§5.2)")
    func nonMinimalLengthRejected() {
        #expect(throws: WebSocketError.nonMinimalLength) {
            try firstFrame([0x82, 126, 0x00, 0x10])  // value 16 would fit the 7-bit form
        }
    }

    // MARK: Helpers

    private func firstFrame(
        _ bytes: [UInt8], maxPayloadLength: Int = 1 << 20
    ) throws
        -> WebSocketFrame?
    {
        let decoder = WebSocketFrameDecoder(maxPayloadLength: maxPayloadLength)
        return try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            return try decoder.nextFrame(&reader)
        }
    }

    private func allFrames(_ bytes: [UInt8]) throws -> [WebSocketFrame] {
        let decoder = WebSocketFrameDecoder()
        return try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            var frames = [WebSocketFrame]()
            while let frame = try decoder.nextFrame(&reader) { frames.append(frame) }
            return frames
        }
    }

    /// A client-style masked frame (RFC 6455 §5.3): MASK bit set, a fixed key, masked payload.
    private func maskedFrame(opcode: WebSocketOpcode, payload: [UInt8]) -> [UInt8] {
        let key: [UInt8] = [0x37, 0xfa, 0x21, 0x3d]
        var wire: [UInt8] = [0x80 | opcode.rawValue, 0x80 | UInt8(payload.count)]
        wire += key
        for (index, byte) in payload.enumerated() { wire.append(byte ^ key[index & 0x3]) }
        return wire
    }
}
