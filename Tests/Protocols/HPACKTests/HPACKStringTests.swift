//
//  HPACKStringTests.swift
//  HPACKTests
//
//  RED→GREEN driver for the RFC 7541 §5.2 string-literal codec: the H flag, the 7-bit length, and the
//  raw vs Huffman choice, anchored on the Appendix C string forms and the §5.2 failure modes.
//

import HTTPCore
import Testing

@testable import HPACK

@Suite("RFC 7541 §5.2 — string literals")
struct HPACKStringTests {
    private func decode(_ bytes: [UInt8], maxEncodedLength: Int = 4_096) throws -> [UInt8] {
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            return try HPACKString.decode(&reader, maxEncodedLength: maxEncodedLength)
        }
    }

    private func decodeString(_ bytes: [UInt8], maxEncodedLength: Int = 4_096) throws -> String {
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            return try HPACKString.decodeString(&reader, maxEncodedLength: maxEncodedLength)
        }
    }

    private func encode(_ string: String) -> [UInt8] {
        var output: [UInt8] = []
        HPACKString.encode(Array(string.utf8), into: &output)
        return output
    }

    // MARK: Appendix C forms

    @Test("encodes a Huffman-shorter string with the H flag set (C.4.1)")
    func encodesHuffman() {
        // "www.example.com" → 0x8c (H=1, length 12) then the Appendix C.4.1 octets.
        let expected: [UInt8] = [
            0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
        ]
        #expect(encode("www.example.com") == expected)
    }

    @Test("encodes as a raw literal when Huffman would not be shorter")
    func encodesRaw() {
        // Byte 0x00 costs 13 Huffman bits (2 octets) > 1 raw octet, so it stays raw: 0x01 0x00.
        var output: [UInt8] = []
        let raw: [UInt8] = [0x00]
        HPACKString.encode(raw, into: &output)
        #expect(output == [0x01, 0x00])
    }

    @Test("decodes a Huffman string literal (C.4.1)")
    func decodesHuffman() throws {
        let literal: [UInt8] = [
            0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
        ]
        #expect(try decode(literal) == Array("www.example.com".utf8))
    }

    @Test("decodes a raw string literal (C.2.1)")
    func decodesRaw() throws {
        let literal: [UInt8] = [0x0a] + Array("custom-key".utf8)  // 0x0a = H=0, length 10
        #expect(try decode(literal) == Array("custom-key".utf8))
    }

    // MARK: Round-trip

    @Test(
        "round-trips strings through encode then decode",
        arguments: [
            "", "a", "custom-key", "custom-value", "www.example.com", "no-cache",
            "Mon, 21 Oct 2013 20:13:21 GMT", "https://www.example.com", "🌍 unicode 世界"
        ])
    func roundTrips(string: String) throws {
        #expect(try decode(encode(string)) == Array(string.utf8))
    }

    @Test(
        "decodeString round-trips straight to String (raw + Huffman, incl. non-ASCII)",
        arguments: [
            "", "a", "custom-key", "www.example.com", "no-cache",
            "Mon, 21 Oct 2013 20:13:21 GMT", "🌍 unicode 世界"
        ])
    func decodeStringRoundTrips(string: String) throws {
        #expect(try decodeString(encode(string)) == string)
    }

    // MARK: §5.2 failure modes

    @Test("a declared length beyond the buffer is a truncation error")
    func truncated() {
        // H=0, length 5, but only three octets follow.
        #expect(throws: HPACKError.truncatedString) { try decode([0x05, 0x61, 0x62, 0x63]) }
    }

    @Test("an empty buffer cannot yield a string")
    func truncatedEmpty() {
        #expect(throws: HPACKError.truncatedString) { try decode([]) }
    }

    @Test("a declared length beyond the maximum fails closed")
    func tooLong() {
        let literal: [UInt8] = [0x0a] + Array("custom-key".utf8)
        #expect(throws: HPACKError.stringTooLong) { try decode(literal, maxEncodedLength: 4) }
    }

    @Test("a Huffman payload that decodes EOS is rejected as invalid")
    func invalidHuffman() {
        // 0x84 = H=1, length 4; four 0xFF octets decode the 30-bit EOS code.
        #expect(throws: HPACKError.invalidHuffman) { try decode([0x84, 0xFF, 0xFF, 0xFF, 0xFF]) }
    }
}
