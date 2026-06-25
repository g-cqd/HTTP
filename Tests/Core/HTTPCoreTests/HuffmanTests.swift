//
//  HuffmanTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for the RFC 7541 §5.2 / Appendix B Huffman codec. The Appendix C worked examples
//  are the external ground truth that validates the generated code table; the all-byte round-trip
//  and the §5.2 failure modes cover the rest.
//

import Testing

@testable import HTTPCore

@Suite("RFC 7541 §5.2 — Huffman coding")
struct HuffmanTests {
    /// RFC 7541 Appendix C worked examples: a string and its exact Huffman-coded octets.
    static let vectors: [(string: String, encoded: [UInt8])] = [
        (
            "www.example.com",
            [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]
        ),
        ("no-cache", [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]),
        ("custom-key", [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f]),
        ("custom-value", [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf]),
        ("302", [0x64, 0x02]),
        ("private", [0xae, 0xc3, 0x77, 0x1a, 0x4b]),
        (
            "Mon, 21 Oct 2013 20:13:21 GMT",
            [
                0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b,
                0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff
            ]
        ),
        (
            "https://www.example.com",
            [
                0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82,
                0xae, 0x43, 0xd3
            ]
        )
    ]

    private func decode(_ bytes: [UInt8]) throws -> [UInt8] {
        try bytes.withUnsafeBytes { try Huffman.decode($0.bytes) }
    }

    // MARK: Appendix C ground truth

    @Test("encodes each Appendix C example to its exact octets", arguments: vectors)
    func encodesVector(string: String, encoded: [UInt8]) {
        #expect(Huffman.encode(Array(string.utf8)) == encoded)
    }

    @Test("decodes each Appendix C example back to its string", arguments: vectors)
    func decodesVector(string: String, encoded: [UInt8]) throws {
        #expect(try decode(encoded) == Array(string.utf8))
    }

    @Test("encodedByteLength agrees with the produced encoding", arguments: vectors)
    func encodedByteLengthMatches(string: String, encoded: [UInt8]) {
        #expect(Huffman.encodedByteLength(of: Array(string.utf8)) == encoded.count)
    }

    // MARK: Round-trip

    @Test("round-trips every single byte value 0...255")
    func roundTripsAllBytes() throws {
        for value in UInt8.min ... UInt8.max {
            #expect(try decode(Huffman.encode([value])) == [value])
        }
    }

    @Test("round-trips a mixed buffer of every byte value")
    func roundTripsMixedBuffer() throws {
        let original = Array(UInt8.min ... UInt8.max) + Array("Hello, 世界! 🌍".utf8)
        #expect(try decode(Huffman.encode(original)) == original)
    }

    @Test("an empty input encodes and decodes to nothing")
    func emptyRoundTrip() throws {
        #expect(Huffman.encode([]).isEmpty)
        #expect(try decode([]).isEmpty)
    }

    // MARK: §5.2 decoding errors

    @Test("the EOS symbol appearing in the input is a decoding error")
    func rejectsEOSInInput() {
        // 32 one-bits: the decoder matches the 30-bit EOS code before the stream ends.
        #expect(throws: HuffmanError.eosInInput) { try decode([0xFF, 0xFF, 0xFF, 0xFF]) }
    }

    @Test("padding longer than 7 bits is a decoding error")
    func rejectsOversizedPadding() {
        // '0' (5 bits) then 11 one-bits of padding — a whole extra octet beyond the 7-bit maximum.
        #expect(throws: HuffmanError.invalidPadding) { try decode([0x07, 0xFF]) }
    }

    @Test("padding that is not the all-ones EOS prefix is a decoding error")
    func rejectsNonOnesPadding() {
        // '0' (5 bits = 00000) then 000 — padding must be 1-bits (the MSBs of EOS), not 0-bits.
        #expect(throws: HuffmanError.invalidPadding) { try decode([0x00]) }
    }
}
