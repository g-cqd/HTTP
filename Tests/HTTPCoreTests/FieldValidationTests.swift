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
