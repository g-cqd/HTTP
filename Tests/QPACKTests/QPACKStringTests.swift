//
//  QPACKStringTests.swift
//  QPACKTests
//
//  RED→GREEN driver for the RFC 9204 §4.1.2 string-literal codec at both prefix widths — the 7-bit
//  value string (H flag at bit 7) and the 3-bit literal-name string (H flag at bit 3) — confirming the
//  H flag is read from the bit just above the length prefix in each case, raw and Huffman-coded.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 §4.1.2 — QPACK string literals")
struct QPACKStringTests {
    private func decode(_ bytes: [UInt8], prefixBits: Int) throws -> String {
        let result: Result<String, QPACKError> = bytes.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in
                var reader = ByteReader(raw)
                return try QPACKString.decodeString(
                    &reader, prefixBits: prefixBits, maxEncodedLength: 4_096
                )
            }
        }
        return try result.get()
    }

    @Test("decodes a raw 7-bit-prefix value string")
    func rawValueString() throws {
        // 0x0B = H=0, length 11; then "/index.html".
        let bytes: [UInt8] = [0x0B] + Array("/index.html".utf8)
        #expect(try decode(bytes, prefixBits: 7) == "/index.html")
    }

    @Test(
        "round-trips raw and Huffman across both prefix widths",
        arguments: [
            "", "/", "www.example.com", "custom-key", "custom-value",
            "no-cache", "Mozilla/5.0 (compatible)"
        ])
    func roundTrip(_ value: String) throws {
        for prefixBits in [3, 7] {
            var out: [UInt8] = []
            QPACKString.encode(Array(value.utf8), prefixBits: prefixBits, firstByte: 0, into: &out)
            #expect(try decode(out, prefixBits: prefixBits) == value)
        }
    }

    @Test("the Huffman form is chosen only when it is shorter (§4.1.2)")
    func huffmanWhenShorter() throws {
        // "www.example.com" compresses under Huffman; the H flag (bit 7) must be set.
        var out: [UInt8] = []
        QPACKString.encode(Array("www.example.com".utf8), prefixBits: 7, firstByte: 0, into: &out)
        #expect(out[0] & 0x80 != 0)
        #expect(try decode(out, prefixBits: 7) == "www.example.com")
    }

    @Test("a length beyond the maximum fails closed with QPACK_DECOMPRESSION_FAILED")
    func oversizedFailsClosed() {
        // 0x7F 0x80 0x01 = length 255 (raw), far past the 8-octet bound below.
        let bytes: [UInt8] = [0x7F, 0x80, 0x01] + [UInt8](repeating: 0x61, count: 255)
        #expect {
            _ = try bytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                return try QPACKString.decodeString(&reader, prefixBits: 7, maxEncodedLength: 8)
            }
        } throws: { error in
            (error as? QPACKError)?.code == .decompressionFailed
        }
    }
}
