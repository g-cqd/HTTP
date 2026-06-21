//
//  ContentLengthTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for RFC 9110 §8.6 / RFC 9112 §6.3 Content-Length interpretation.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §8.6 — Content-Length")
struct ContentLengthTests {

    private func fields(contentLength values: String...) -> HTTPFields {
        var fields = HTTPFields()
        for value in values {
            fields.append(value, for: .contentLength)
        }
        return fields
    }

    @Test("absent when no Content-Length is present")
    func absent() {
        #expect(HTTPFields().contentLength == .absent)
    }

    @Test("parses a single non-negative value")
    func singleValue() {
        #expect(fields(contentLength: "42").contentLength == .length(42))
        #expect(fields(contentLength: "0").contentLength == .length(0))
    }

    @Test("trims surrounding optional whitespace (OWS)")
    func trimsWhitespace() {
        #expect(fields(contentLength: "  7\t").contentLength == .length(7))
    }

    @Test(
        "rejects non-numeric or signed values (RFC 9110 §8.6)",
        arguments: ["abc", "1a", "-5", "+5", "5.0", "0x10", "", " ", "1 2"]
    )
    func invalidValues(_ value: String) {
        #expect(fields(contentLength: value).contentLength == .invalid)
    }

    @Test("rejects conflicting duplicate Content-Length (smuggling, RFC 9112 §6.3)")
    func conflictingDuplicates() {
        #expect(fields(contentLength: "5", "6").contentLength == .invalid)
    }

    @Test("collapses identical duplicate values to one length")
    func identicalDuplicates() {
        #expect(fields(contentLength: "5", "5").contentLength == .length(5))
    }

    @Test("rejects a comma-combined list with differing values (HTTP/2 down-conversion)")
    func commaListDiffering() {
        #expect(fields(contentLength: "5, 6").contentLength == .invalid)
    }

    @Test("accepts a comma-combined list of identical values")
    func commaListIdentical() {
        #expect(fields(contentLength: "5, 5").contentLength == .length(5))
    }
}
