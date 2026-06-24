//
//  HPACKIntegerTests.swift
//  HPACKTests
//
//  RED→GREEN driver for the RFC 7541 §5.1 prefix-integer codec, anchored on the worked examples in
//  Appendix C.1 and the overflow / truncation failure modes §5.1 mandates.
//

import HTTPCore
import Testing

@testable import HPACK

@Suite("RFC 7541 §5.1 — prefix integers")
struct HPACKIntegerTests {
    private func decode(_ bytes: [UInt8], prefixBits: Int) throws -> Int {
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            return try HPACKInteger.decode(&reader, prefixBits: prefixBits)
        }
    }

    private func encode(_ value: Int, prefixBits: Int) -> [UInt8] {
        var output: [UInt8] = []
        HPACKInteger.encode(value, prefixBits: prefixBits, into: &output)
        return output
    }

    // MARK: Appendix C.1 worked examples

    @Test("C.1.1 — encodes 10 in a 5-bit prefix as a single octet")
    func encodesExampleC11() {
        #expect(encode(10, prefixBits: 5) == [0x0A])
    }

    @Test("C.1.2 — encodes 1337 in a 5-bit prefix with two continuation octets")
    func encodesExampleC12() {
        #expect(encode(1_337, prefixBits: 5) == [0x1F, 0x9A, 0x0A])
    }

    @Test("C.1.3 — encodes 42 starting at an octet boundary (8-bit prefix)")
    func encodesExampleC13() {
        #expect(encode(42, prefixBits: 8) == [0x2A])
    }

    @Test("C.1 — decodes each worked example back to its value")
    func decodesExamples() throws {
        #expect(try decode([0x0A], prefixBits: 5) == 10)
        #expect(try decode([0x1F, 0x9A, 0x0A], prefixBits: 5) == 1_337)
        #expect(try decode([0x2A], prefixBits: 8) == 42)
    }

    // MARK: Boundaries & round-trip

    @Test(
        "round-trips across prefixes and boundary values",
        arguments: [
            (0, 5), (1, 5), (30, 5), (31, 5), (32, 5), (1_337, 5),
            (0, 1), (1, 1), (127, 7), (128, 7), (254, 8), (255, 8), (256, 8),
            (HPACKInteger.maxValue, 5), (HPACKInteger.maxValue, 8)
        ])
    func roundTrips(value: Int, prefixBits: Int) throws {
        #expect(try decode(encode(value, prefixBits: prefixBits), prefixBits: prefixBits) == value)
    }

    @Test("the high flag bits above the prefix do not affect the decoded value")
    func ignoresFlagBits() throws {
        // 0xEA = 11101010: a 5-bit prefix sees 01010 = 10 regardless of the 111 flags above it.
        #expect(try decode([0xEA], prefixBits: 5) == 10)
    }

    // MARK: Failure modes (RFC 7541 §5.1)

    @Test("a stream that ends mid-continuation is a truncation error")
    func truncatedContinuation() {
        // 5-bit prefix all-ones signals continuation, but no continuation octet follows.
        #expect(throws: HPACKError.truncatedInteger) {
            try decode([0x1F], prefixBits: 5)
        }
    }

    @Test("an empty stream cannot yield an integer")
    func truncatedFirstOctet() {
        #expect(throws: HPACKError.truncatedInteger) {
            try decode([], prefixBits: 7)
        }
    }

    @Test("an endless run of continuation octets fails closed (overflow guard)")
    func overflowPaddingAttack() {
        // 0x1F prefix then 0x80 0x80 0x80 ... — continuation bit forever, never terminating.
        let attack: [UInt8] = [0x1F, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]
        #expect(throws: HPACKError.integerOverflow) {
            try decode(attack, prefixBits: 5)
        }
    }
}
