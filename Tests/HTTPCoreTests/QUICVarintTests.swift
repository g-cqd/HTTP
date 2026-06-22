//
//  QUICVarintTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for the RFC 9000 §16 variable-length integer codec, including the Appendix A.1
//  sample decodings and the boundary lengths of the 1/2/4/8-octet forms.
//

import Testing

@testable import HTTPCore

@Suite("QUICVarint — RFC 9000 §16 variable-length integer")
struct QUICVarintTests {

    /// Decodes `bytes` and reports the value with how many octets the reader consumed.
    private func decode(_ bytes: [UInt8]) -> (value: UInt64?, consumed: Int) {
        bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let value = QUICVarint.decode(&reader)
            return (value, reader.position)
        }
    }

    @Test(
        "RFC 9000 Appendix A.1 sample decodings",
        arguments: [
            // The four worked examples from RFC 9000 Appendix A.1.
            (
                bytes: [0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C],
                value: 151_288_809_941_952_652
            ),
            (bytes: [0x9D, 0x7F, 0x3E, 0x7D], value: 494_878_333),
            (bytes: [0x7B, 0xBD], value: 15_293),
            (bytes: [0x25], value: 37),
        ] as [(bytes: [UInt8], value: UInt64)])
    func appendixA1(_ testCase: (bytes: [UInt8], value: UInt64)) {
        let (value, consumed) = decode(testCase.bytes)
        #expect(value == testCase.value)
        #expect(consumed == testCase.bytes.count)
    }

    @Test("a non-minimal encoding decodes to the same value (RFC 9000 §16)")
    func nonMinimalDecode() {
        // `40 25` is the two-octet form of 37, which minimally fits in one octet — still valid input.
        let (value, consumed) = decode([0x40, 0x25])
        #expect(value == 37)
        #expect(consumed == 2)
    }

    @Test(
        "encode is minimal and round-trips",
        arguments: [
            (value: 0, length: 1), (value: 63, length: 1),
            (value: 64, length: 2), (value: 16_383, length: 2),
            (value: 16_384, length: 4), (value: 1_073_741_823, length: 4),
            (value: 1_073_741_824, length: 8), (value: QUICVarint.maxValue, length: 8),
        ] as [(value: UInt64, length: Int)])
    func encodeRoundTrips(_ testCase: (value: UInt64, length: Int)) {
        var out = [UInt8]()
        QUICVarint.encode(testCase.value, into: &out)
        #expect(out.count == testCase.length)
        #expect(QUICVarint.encodedLength(of: testCase.value) == testCase.length)
        let (decoded, consumed) = decode(out)
        #expect(decoded == testCase.value)
        #expect(consumed == testCase.length)
    }

    @Test("the encoded length is read from the first octet's two high bits (RFC 9000 §16)")
    func encodedLengthFromFirstByte() {
        #expect(QUICVarint.encodedLength(firstByte: 0x00) == 1)  // 0b00…
        #expect(QUICVarint.encodedLength(firstByte: 0x40) == 2)  // 0b01…
        #expect(QUICVarint.encodedLength(firstByte: 0x80) == 4)  // 0b10…
        #expect(QUICVarint.encodedLength(firstByte: 0xC0) == 8)  // 0b11…
    }

    @Test("a truncated varint returns nil and leaves the reader unmoved")
    func truncatedReturnsNil() {
        // First octet says four-octet form, but only one octet is present.
        let (value, consumed) = decode([0x80])
        #expect(value == nil)
        #expect(consumed == 0)
    }

    @Test("an empty buffer decodes to nil")
    func emptyDecodesNil() {
        let (value, consumed) = decode([])
        #expect(value == nil)
        #expect(consumed == 0)
    }

    @Test("two varints decode back-to-back from one buffer")
    func sequentialDecode() {
        var out = [UInt8]()
        QUICVarint.encode(0x41, into: &out)  // type byte
        QUICVarint.encode(1_073_741_824, into: &out)  // length
        out.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let first = QUICVarint.decode(&reader)
            let second = QUICVarint.decode(&reader)
            #expect(first == 0x41)
            #expect(second == 1_073_741_824)
            let atEnd = reader.isAtEnd
            #expect(atEnd)
        }
    }
}
