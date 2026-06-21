//
//  HTTPFieldTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for RFC 9110 §5 field construction & value validation.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §5 — HTTPField")
struct HTTPFieldTests {

    @Test("constructs a field with a name and a legal value")
    func constructsField() {
        let field = HTTPField(name: .contentType, value: "text/html; charset=utf-8")
        #expect(field?.name == .contentType)
        #expect(field?.value == "text/html; charset=utf-8")
    }

    @Test("the string-name initializer validates and canonicalizes the name")
    func stringNameInitializer() {
        #expect(HTTPField(name: "Content-Type", value: "text/html")?.name == .contentType)
        #expect(HTTPField(name: "bad name", value: "x") == nil)
    }

    @Test(
        "rejects values containing CR, LF or NUL (injection defense, RFC 9110 §5.5)",
        arguments: ["a\r\nb", "a\rb", "a\nb", "a\u{00}b"]
    )
    func rejectsIllegalValues(_ value: String) {
        #expect(HTTPField(name: .contentType, value: value) == nil)
    }
}
