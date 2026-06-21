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
            [0x76, 0x00, 0x61],  // embedded NUL
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
}
