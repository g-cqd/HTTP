//
//  WebSocketUTF8ValidationTests.swift
//  WebSocketTests
//
//  RFC 6455 §8.1 / RFC 3629 — the text-frame UTF-8 well-formedness check, exercised through the
//  connection engine: well-formed sequences surface a `.message` event; ill-formed ones fail with
//  `.invalidTextEncoding`. Guards the allocation-free validator against overlong forms, surrogates,
//  out-of-range code points, and truncated / stray continuation bytes.
//

import Testing

@testable import WebSocket

@Suite("RFC 6455 §8.1 — text UTF-8 validation")
struct WebSocketUTF8ValidationTests {

    /// A masked client text frame (FIN, opcode 0x1) carrying `payload` (≤ 125 octets).
    private func maskedTextFrame(_ payload: [UInt8]) -> [UInt8] {
        let key: [UInt8] = [0x1A, 0x2B, 0x3C, 0x4D]
        var wire: [UInt8] = [0x81, 0x80 | UInt8(payload.count)]
        wire.append(contentsOf: key)
        for (offset, byte) in payload.enumerated() { wire.append(byte ^ key[offset & 3]) }
        return wire
    }

    static let valid: [[UInt8]] = [
        [],  // empty payload
        Array("hello".utf8),  // ASCII
        Array("café".utf8),  // 2-byte (é)
        Array("日本語".utf8),  // 3-byte
        Array("🦊".utf8),  // 4-byte
        [0xED, 0x9F, 0xBF],  // U+D7FF — just below the surrogate range
        [0xEE, 0x80, 0x80],  // U+E000 — just above the surrogate range
        [0xF4, 0x8F, 0xBF, 0xBF],  // U+10FFFF — the maximum code point
    ]

    static let invalid: [[UInt8]] = [
        [0x80],  // lone continuation byte
        [0xFF],  // invalid lead byte
        [0xC1, 0x80],  // overlong 2-byte
        [0xC0, 0x80],  // overlong NUL
        [0xE0, 0x80, 0x80],  // overlong 3-byte
        [0xED, 0xA0, 0x80],  // UTF-16 surrogate U+D800
        [0xF0, 0x80, 0x80, 0x80],  // overlong 4-byte
        [0xF4, 0x90, 0x80, 0x80],  // U+110000 — beyond U+10FFFF
        [0xE2, 0x82],  // truncated 3-byte
        [0xC2],  // truncated 2-byte
        [0x68, 0xC3, 0x28],  // valid byte, then a bad continuation
    ]

    @Test("well-formed UTF-8 text is accepted (RFC 3629)", arguments: valid)
    func acceptsValid(payload: [UInt8]) throws {
        var connection = WebSocketConnection()
        let events = try connection.receive(maskedTextFrame(payload))
        #expect(events == [.message(opcode: .text, payload: payload)])
    }

    @Test("ill-formed UTF-8 text is rejected with .invalidTextEncoding (§8.1)", arguments: invalid)
    func rejectsInvalid(payload: [UInt8]) {
        var connection = WebSocketConnection()
        var thrown: WebSocketError?
        do { _ = try connection.receive(maskedTextFrame(payload)) } catch { thrown = error }
        #expect(thrown == .invalidTextEncoding)
    }
}
