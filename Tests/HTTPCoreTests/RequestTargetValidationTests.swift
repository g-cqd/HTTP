//
//  RequestTargetValidationTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for RFC 9112 §3.2 / RFC 9113 §8.3.1 request-target / pseudo-header validation.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9112 §3.2 / RFC 9113 §8.3.1 — request-target / pseudo-header validation")
struct RequestTargetValidationTests {
    /// The SWAR fast path MUST agree with the scalar predicate for every byte at every position and
    /// length — this is a security validator (injection defense), so a single divergence is a hole.
    @Test("SWAR agrees with the scalar predicate for all 256 bytes across word/tail boundaries")
    func swarMatchesScalar() {
        for byte in UInt8.min ... UInt8.max {
            let scalarValid = FieldValidation.isRequestTargetByte(byte)
            // Lengths chosen to span the 8-octet SWAR word boundary and the scalar tail.
            for length in [1, 7, 8, 9, 13, 16] {
                for position in 0 ..< length {
                    var buffer = [UInt8](repeating: 0x61, count: length)  // 'a' — valid
                    buffer[position] = byte
                    #expect(
                        FieldValidation.isRequestTargetValue(buffer) == scalarValid,
                        "byte \(byte) at position \(position) of length \(length)")
                }
            }
        }
    }

    @Test("accepts VCHAR + obs-text; rejects controls, SP, DEL, CR, LF, NUL")
    func acceptsAndRejects() {
        #expect(FieldValidation.isRequestTargetValue(Array("/index.html?q=1&x=%20".utf8)))
        #expect(FieldValidation.isRequestTargetValue([0x80, 0xA0, 0xFF]))  // obs-text is valid
        #expect(FieldValidation.isRequestTargetValue([UInt8]()))  // empty is vacuously valid
        for bad: UInt8 in [0x00, 0x09, 0x0A, 0x0D, 0x1F, 0x20, 0x7F] {
            #expect(!FieldValidation.isRequestTargetValue([0x2F, bad, 0x2F]))  // bad byte mid-path
        }
    }
}
