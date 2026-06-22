//
//  QPACKIntegerTests.swift
//  QPACKTests
//
//  RED→GREEN driver for the RFC 9204 §4.1.1 prefix-integer codec (the RFC 7541 §5.1 representation),
//  including the RFC 7541 Appendix C.1 worked examples and the incomplete / overflow outcomes that the
//  field-section and instruction parsers must distinguish.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 §4.1.1 — QPACK prefix integers")
struct QPACKIntegerTests {

    private func decode(_ bytes: [UInt8], prefixBits: Int) -> QPACKInteger.Outcome {
        bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            return QPACKInteger.decode(&reader, prefixBits: prefixBits)
        }
    }

    @Test(
        "RFC 7541 Appendix C.1 worked examples encode to the exact octets",
        arguments: [
            (value: 10, prefixBits: 5, bytes: [0x0A] as [UInt8]),  // C.1.1
            (value: 1337, prefixBits: 5, bytes: [0x1F, 0x9A, 0x0A]),  // C.1.2
            (value: 42, prefixBits: 8, bytes: [0x2A]),  // C.1.3
        ] as [(value: Int, prefixBits: Int, bytes: [UInt8])])
    func appendixC1(_ testCase: (value: Int, prefixBits: Int, bytes: [UInt8])) {
        var out = [UInt8]()
        QPACKInteger.encode(testCase.value, prefixBits: testCase.prefixBits, into: &out)
        #expect(out == testCase.bytes)
        #expect(decode(testCase.bytes, prefixBits: testCase.prefixBits) == .value(testCase.value))
    }

    @Test(
        "encode round-trips across prefix widths",
        arguments: [0, 1, 30, 31, 127, 128, 16_383, 1_000_000, QPACKInteger.maxValue])
    func roundTrip(_ value: Int) {
        for prefixBits in [3, 4, 5, 6, 7, 8] {
            var out = [UInt8]()
            QPACKInteger.encode(value, prefixBits: prefixBits, firstByte: 0, into: &out)
            #expect(decode(out, prefixBits: prefixBits) == .value(value))
        }
    }

    @Test("a truncated integer reports .incomplete (need more bytes)")
    func truncated() {
        #expect(decode([], prefixBits: 5) == .incomplete)
        // 0x1F fills a 5-bit prefix, demanding at least one continuation octet that never arrives.
        #expect(decode([0x1F], prefixBits: 5) == .incomplete)
        #expect(decode([0x1F, 0x80], prefixBits: 5) == .incomplete)
    }

    @Test("an oversized integer reports .overflow")
    func overflow() {
        // A run of continuation octets past the magnitude bound is a §5.1 oversized-length fault.
        #expect(decode([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], prefixBits: 8) == .overflow)
    }

    @Test("flag bits above the prefix are ignored on decode")
    func ignoresFlagBits() {
        // 0xEA = 1110 1010: with a 5-bit prefix the value is the low 5 bits (0x0A = 10).
        #expect(decode([0xEA], prefixBits: 5) == .value(10))
    }
}
