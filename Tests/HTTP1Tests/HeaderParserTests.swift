//
//  HeaderParserTests.swift
//  HTTP1Tests
//
//  RED→GREEN driver for RFC 9112 §5 header-field parsing and its smuggling defenses.
//

import HTTPCore
import Testing

@testable import HTTP1

@Suite("RFC 9112 §5 — header-field parsing")
struct HeaderParserTests {

    /// Parses the header section of `string` through a `ByteReader` borrowing its bytes (zero-copy).
    private func parseHeaders(_ string: String, limits: HTTPLimits = .default) throws -> HTTPFields
    {
        let bytes = Array(string.utf8)
        return try bytes.withUnsafeBytes { raw -> HTTPFields in
            var reader = ByteReader(raw)
            return try HeaderParser.parse(&reader, limits: limits)
        }
    }

    @Test("parses field-lines into ordered fields")
    func parsesFields() throws {
        let fields = try parseHeaders("Host: example.com\r\nContent-Type: text/plain\r\n\r\n")
        #expect(fields.count == 2)
        #expect(fields[.host] == "example.com")
        #expect(fields[.contentType] == "text/plain")
        #expect(fields.map(\.name) == [.host, .contentType])
    }

    @Test("trims optional whitespace around the value (RFC 9112 §5)")
    func trimsValueWhitespace() throws {
        let fields = try parseHeaders("Host:   example.com\t \r\n\r\n")
        #expect(fields[.host] == "example.com")
    }

    @Test("an empty header section parses to no fields")
    func emptySection() throws {
        let fields = try parseHeaders("\r\n")
        #expect(fields.isEmpty)
    }

    @Test("preserves repeated field lines (RFC 9110 §5.3)")
    func repeatedFields() throws {
        let fields = try parseHeaders("Accept: text/html\r\nAccept: application/json\r\n\r\n")
        #expect(fields.values(for: .accept) == ["text/html", "application/json"])
    }

    @Test("rejects obsolete line folding (smuggling, RFC 9112 §5.2)")
    func rejectsObsoleteFolding() {
        #expect(throws: HTTP1ParseError.obsoleteLineFolding) {
            try parseHeaders("Host: example.com\r\n folded\r\n\r\n")
        }
    }

    @Test("rejects whitespace before the colon (smuggling, RFC 9112 §5.1)")
    func rejectsWhitespaceBeforeColon() {
        #expect(throws: HTTP1ParseError.invalidFieldName) {
            try parseHeaders("Host : example.com\r\n\r\n")
        }
    }

    @Test("rejects a field-line with no colon")
    func rejectsMissingColon() {
        #expect(throws: HTTP1ParseError.missingColon) {
            try parseHeaders("InvalidLine\r\n\r\n")
        }
    }

    @Test("enforces the maximum field count (→ 431)")
    func enforcesFieldCount() {
        let limits = HTTPLimits(maxFieldCount: 1)
        #expect(throws: HTTP1ParseError.tooManyFields) {
            try parseHeaders("A: 1\r\nB: 2\r\n\r\n", limits: limits)
        }
    }
}
