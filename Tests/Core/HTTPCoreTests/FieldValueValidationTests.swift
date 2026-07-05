//
//  FieldValueValidationTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for RFC 9110 §5.5 `field-value` legality (the CR/LF/NUL injection defense).
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §5.5 — field-value legality")
struct FieldValueValidationTests {
    @Test("accepts the empty value (*field-content)")
    func acceptsEmpty() {
        #expect(FieldValidation.isValidFieldValue([UInt8]()))
    }

    @Test("accepts a typical header value")
    func acceptsTypicalValue() {
        #expect(FieldValidation.isValidFieldValue(Array("text/html; charset=utf-8".utf8)))
    }

    @Test("accepts internal HTAB and SP")
    func acceptsInternalWhitespace() {
        #expect(FieldValidation.isValidFieldValue(Array("gzip,\tdeflate, br".utf8)))
    }

    @Test("accepts obs-text (0x80...0xFF)")
    func acceptsObsText() {
        // "é" in UTF-8 is 0xC3 0xA9 — both in the obs-text range.
        #expect(FieldValidation.isValidFieldValue([0xC3, 0xA9]))
        #expect(FieldValidation.isValidFieldValue([0x80, 0xFF]))
    }

    @Test(
        "rejects CR, LF and NUL (response splitting / injection, CWE-113)",
        arguments: [
            [UInt8](("value\r\nInjected: x".utf8)),  // CRLF injection
            [UInt8](("value\rmore".utf8)),  // bare CR
            [UInt8](("value\nmore".utf8)),  // bare LF
            [0x76, 0x00, 0x61]  // embedded NUL
        ] as [[UInt8]]
    )
    func rejectsCRLFNUL(_ bytes: [UInt8]) {
        #expect(!FieldValidation.isValidFieldValue(bytes))
    }

    @Test(
        "rejects other C0 controls and DEL",
        arguments: [0x00, 0x07, 0x0B, 0x0C, 0x1F, 0x7F] as [UInt8]
    )
    func rejectsControls(_ byte: UInt8) {
        #expect(!FieldValidation.isFieldValueByte(byte))
    }

    @Test("classifies boundary bytes correctly")
    func boundaryBytes() {
        #expect(FieldValidation.isFieldValueByte(0x09))  // HTAB allowed
        #expect(!FieldValidation.isFieldValueByte(0x08))  // BS rejected
        #expect(FieldValidation.isFieldValueByte(0x20))  // SP allowed
        #expect(FieldValidation.isFieldValueByte(0x7E))  // "~" allowed
        #expect(!FieldValidation.isFieldValueByte(0x7F))  // DEL rejected
        #expect(FieldValidation.isFieldValueByte(0x80))  // obs-text start allowed
    }

    /// SWAR contiguous validation must match the per-octet classifier for every byte value.
    ///
    /// Places each value 0–255 at every lane offset — covering each of the eight word lanes and the
    /// `< 8`-octet scalar tail — to guard the bit-trick against an off-by-one or a boundary slip.
    @Test("SWAR contiguous validation matches the per-octet classifier for all 256 bytes × offsets")
    func swarMatchesScalarForEveryByte() {
        let filler: UInt8 = 0x61  // 'a', a valid VCHAR
        for value in UInt8.min ... UInt8.max {
            for prefix in 0 ... 17 {  // span the lanes + word/tail boundary
                var bytes = [UInt8](repeating: filler, count: prefix)
                bytes.append(value)
                bytes.append(contentsOf: [UInt8](repeating: filler, count: 3))
                #expect(
                    FieldValidation.isValidFieldValue(bytes)
                        == FieldValidation.isFieldValueByte(value))
            }
        }
    }

    /// The SIMD kernel path (values ≥ 64 B) must match the per-octet classifier for every byte at
    /// every lane/chunk offset across the 16/32-byte SIMD bodies and the scalar tail.
    @Test("Kernel field-value validation matches the classifier for long values")
    func kernelFieldValueMatchesClassifier() {
        let filler: UInt8 = 0x61  // 'a'
        for value in UInt8.min ... UInt8.max {
            for offset in [0, 1, 15, 16, 17, 31, 32, 33, 47, 63, 64, 71] {  // 72-byte buffer ⇒ kernel
                var bytes = [UInt8](repeating: filler, count: 72)
                bytes[offset] = value
                #expect(
                    FieldValidation.isValidFieldValue(bytes)
                        == FieldValidation.isFieldValueByte(value))
            }
        }
    }

    @Test("Kernel request-target validation matches the classifier for long values")
    func kernelRequestTargetMatchesClassifier() {
        let filler: UInt8 = 0x61
        for value in UInt8.min ... UInt8.max {
            for offset in [0, 1, 16, 32, 33, 48, 63, 64, 71] {  // 72-byte buffer ⇒ kernel
                var bytes = [UInt8](repeating: filler, count: 72)
                bytes[offset] = value
                #expect(
                    FieldValidation.isRequestTargetValue(bytes)
                        == FieldValidation.isRequestTargetByte(value))
            }
        }
    }
}
