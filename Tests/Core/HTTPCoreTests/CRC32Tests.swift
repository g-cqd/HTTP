//
//  CRC32Tests.swift
//  HTTPCoreTests
//
//  RFC 1952 §8 — the gzip CRC-32, checked against the canonical ITU-T V.42 vectors.
//

import Testing

@testable import HTTPCore

@Suite("RFC 1952 §8 — CRC-32")
struct CRC32Tests {
    @Test("the empty input has CRC-32 zero")
    func empty() {
        #expect(CRC32.checksum([UInt8]()) == 0)
    }

    @Test("the standard check string yields 0xCBF43926")
    func standardCheckValue() {
        #expect(CRC32.checksum(Array("123456789".utf8)) == 0xCBF4_3926)
    }

    @Test("a known short string matches the reference CRC-32")
    func knownString() {
        // CRC-32 of "The quick brown fox jumps over the lazy dog" (reference value).
        let input = Array("The quick brown fox jumps over the lazy dog".utf8)
        #expect(CRC32.checksum(input) == 0x414F_A339)
    }
}
