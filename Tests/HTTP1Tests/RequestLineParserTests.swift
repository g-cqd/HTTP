//
//  RequestLineParserTests.swift
//  HTTP1Tests
//
//  RED→GREEN driver for RFC 9112 §3 request-line parsing.
//

import HTTPCore
import Testing

@testable import HTTP1

@Suite("RFC 9112 §3 — request-line parsing")
struct RequestLineParserTests {

    /// Parses `string` through a `ByteReader` borrowing its UTF-8 bytes (zero-copy).
    private func parseLine(_ string: String) throws -> RequestLine {
        let bytes = Array(string.utf8)
        return try bytes.withUnsafeBytes { raw -> RequestLine in
            var reader = ByteReader(raw)
            return try RequestLineParser.parse(&reader)
        }
    }

    @Test("parses a well-formed request-line")
    func parsesValid() throws {
        let line = try parseLine("GET /path?q=1 HTTP/1.1\r\n")
        #expect(line.method == .get)
        #expect(line.target == "/path?q=1")
        #expect(line.version == .http11)
    }

    @Test("parses HTTP/1.0")
    func parsesHTTP10() throws {
        let line = try parseLine("HEAD / HTTP/1.0\r\n")
        #expect(line.method == .head)
        #expect(line.target == "/")
        #expect(line.version == .http10)
    }

    @Test(
        "rejects malformed request-lines",
        arguments: [
            "",  // empty
            "GET /path",  // no SP-version / CRLF
            "GET /path HTTP/1.1",  // missing CRLF terminator
            "GET /path BANANA\r\n",  // unrecognized version token
        ]
    )
    func rejectsMalformed(_ input: String) {
        #expect(throws: HTTP1ParseError.self) { try parseLine(input) }
    }

    @Test("rejects a non-token method (RFC 9110 §9.1)")
    func rejectsInvalidMethod() {
        #expect(throws: HTTP1ParseError.invalidMethod) {
            try parseLine("G@T /path HTTP/1.1\r\n")
        }
    }

    @Test("rejects an empty request-target")
    func rejectsEmptyTarget() {
        #expect(throws: HTTP1ParseError.invalidTarget) {
            try parseLine("GET  HTTP/1.1\r\n")
        }
    }

    @Test(
        "rejects control characters in the request-target (injection, RFC 9112 §3.2)",
        arguments: [
            "GET /a\u{01}b HTTP/1.1\r\n",  // C0 control
            "GET /a\rb HTTP/1.1\r\n",  // bare CR embedded in the target
            "GET /a\u{7F}b HTTP/1.1\r\n",  // DEL
        ]
    )
    func rejectsControlInTarget(_ input: String) {
        #expect(throws: HTTP1ParseError.invalidTarget) { try parseLine(input) }
    }
}
