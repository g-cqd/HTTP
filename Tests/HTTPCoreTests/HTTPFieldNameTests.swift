//
//  HTTPFieldNameTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for RFC 9110 §5.1 field-name case-insensitivity & canonicalization.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §5.1 — HTTPFieldName")
struct HTTPFieldNameTests {
    @Test("canonical form is ASCII lower-case (HTTP/2 & HTTP/3 wire form)")
    func canonicalIsLowercased() {
        #expect(HTTPFieldName("Content-Type")?.canonicalName == "content-type")
        #expect(HTTPFieldName("ETag")?.canonicalName == "etag")
        #expect(HTTPFieldName("X-Custom-HEADER")?.canonicalName == "x-custom-header")
    }

    @Test("the original spelling is preserved for HTTP/1.1 rendering")
    func rawNamePreserved() {
        #expect(HTTPFieldName("Content-Type")?.rawName == "Content-Type")
    }

    @Test("registered constants keep their StaticString spelling (zero-allocation path)")
    func constantStorageIsLiteral() {
        #expect(HTTPFieldName.contentType.rawName == "content-type")
        guard case .literal = HTTPFieldName.contentType.storage else {
            Issue.record("expected a registered constant to use literal (StaticString) storage")
            return
        }
    }

    @Test("a runtime-parsed name uses String storage")
    func parsedStorageIsDynamic() throws {
        let name = try #require(HTTPFieldName("X-Request-Id"))
        guard case .parsed = name.storage else {
            Issue.record("expected a runtime name to use parsed (String) storage")
            return
        }
        #expect(name.rawName == "X-Request-Id")
    }

    @Test("equality and hashing are case-insensitive (RFC 9110 §5.1)")
    func caseInsensitiveEquality() {
        let upper = HTTPFieldName("Content-Type")
        let lower = HTTPFieldName("content-type")
        let mixed = HTTPFieldName("CoNtEnT-tYpE")
        #expect(upper == lower)
        #expect(upper == mixed)
        #expect(Set([upper, lower, mixed]).count == 1)
    }

    @Test("distinct names are not equal")
    func distinctNames() {
        #expect(HTTPFieldName("content-type") != HTTPFieldName("content-length"))
    }

    @Test("registered constants are stored canonically")
    func registeredConstants() {
        #expect(HTTPFieldName.contentType.canonicalName == "content-type")
        #expect(HTTPFieldName.setCookie.canonicalName == "set-cookie")
        #expect(HTTPFieldName("CONTENT-TYPE") == .contentType)
    }

    @Test("rejects non-token names", arguments: ["", "Content Type", "Content:Type", "näme"])
    func rejectsNonTokens(_ name: String) {
        #expect(HTTPFieldName(name) == nil)
    }

    @Test("validating(bytes:) accepts a token, canonicalizes it, and rejects non-tokens")
    func validatingBytes() {
        let mixed = HTTPFieldName(validating: Array("Content-Type".utf8))
        #expect(mixed?.canonicalName == "content-type")
        #expect(mixed?.rawName == "Content-Type")
        let lower = HTTPFieldName(validating: Array("accept".utf8))
        #expect(lower?.canonicalName == "accept")
        #expect(HTTPFieldName(validating: Array("bad name".utf8)) == nil)
        #expect(HTTPFieldName(validating: [UInt8]()) == nil)
    }
}
