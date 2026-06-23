//
//  FieldValidationTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for RFC 9110 §5.6.2 `token` validation.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §5.6.2 — token validation")
struct FieldValidationTests {

    @Test("accepts a typical lowercase field-name")
    func acceptsTypicalFieldName() {
        #expect(FieldValidation.isToken(Array("content-type".utf8)))
    }

    @Test("accepts every tchar special, DIGIT and ALPHA")
    func acceptsAllTchars() {
        // All RFC 9110 §5.6.2 specials plus a DIGIT and ALPHA boundary sample.
        #expect(FieldValidation.isToken(Array("!#$%&'*+-.^_`|~0Az".utf8)))
    }

    @Test("rejects the empty sequence (token is 1*tchar)")
    func rejectsEmpty() {
        #expect(!FieldValidation.isToken([UInt8]()))
    }

    @Test(
        "rejects separators, whitespace and control bytes",
        arguments: [
            "content type",  // SP separator
            "content:type",  // ":" separator
            "name\r",  // bare CR (smuggling)
            "name\n",  // bare LF (smuggling)
            "na\u{00}me",  // NUL
            "(comment)",  // "(" / ")" separators
            "name=value",  // "=" separator
            "naïve",  // non-ASCII (> 0x7F)
        ]
    )
    func rejectsInvalid(_ value: String) {
        #expect(!FieldValidation.isToken(Array(value.utf8)))
    }
}

@Suite("RFC 9112 §3.2 / RFC 9113 §8.3.1 — request-target / pseudo-header validation")
struct RequestTargetValidationTests {

    /// The SWAR fast path MUST agree with the scalar predicate for every byte at every position and
    /// length — this is a security validator (injection defense), so a single divergence is a hole.
    @Test("SWAR agrees with the scalar predicate for all 256 bytes across word/tail boundaries")
    func swarMatchesScalar() {
        for byte in UInt8.min...UInt8.max {
            let scalarValid = FieldValidation.isRequestTargetByte(byte)
            // Lengths chosen to span the 8-octet SWAR word boundary and the scalar tail.
            for length in [1, 7, 8, 9, 13, 16] {
                for position in 0..<length {
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
