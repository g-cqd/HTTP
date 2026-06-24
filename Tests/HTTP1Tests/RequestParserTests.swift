//
//  RequestParserTests.swift
//  HTTP1Tests
//
//  RED→GREEN driver for the full RFC 9112 request parse, including the request-smuggling defenses
//  (CL vs TE precedence, §6.1) and the mandatory Host header (RFC 9110 §7.2).
//

import HTTPCore
import Testing

@testable import HTTP1

@Suite("RFC 9112 — full request parsing & smuggling defenses")
struct RequestParserTests {
    private func parse(_ string: String, limits: HTTPLimits = .default) throws -> ParsedRequest {
        let bytes = Array(string.utf8)
        return try bytes.withUnsafeBytes { raw -> ParsedRequest in
            var reader = ByteReader(raw)
            return try RequestParser.parse(&reader, limits: limits)
        }
    }

    @Test("parses a bodyless GET request")
    func parsesGet() throws {
        let parsed = try parse("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        #expect(parsed.request.method == .get)
        #expect(parsed.request.path == "/path")
        #expect(parsed.request.authority == "example.com")
        #expect(parsed.request.effectiveAuthority == "example.com")
        #expect(parsed.body.isEmpty)
    }

    @Test("parses a Content-Length delimited body")
    func parsesContentLengthBody() throws {
        let parsed = try parse(
            "POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        #expect(String(decoding: parsed.body, as: UTF8.self) == "hello")
    }

    @Test("parses a chunked body (RFC 9112 §6.1 / §7.1)")
    func parsesChunkedBody() throws {
        let parsed = try parse(
            "POST /submit HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                + "5\r\nhello\r\n0\r\n\r\n")
        #expect(String(decoding: parsed.body, as: UTF8.self) == "hello")
    }

    @Test("rejects Content-Length AND Transfer-Encoding together (smuggling, RFC 9112 §6.1)")
    func rejectsContentLengthAndTransferEncoding() {
        #expect(throws: HTTP1ParseError.contentLengthWithTransferEncoding) {
            try parse(
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + "5\r\nhello\r\n0\r\n\r\n")
        }
    }

    @Test("rejects an HTTP/1.1 request with no Host (RFC 9110 §7.2)")
    func rejectsMissingHost() {
        #expect(throws: HTTP1ParseError.invalidHost) {
            try parse("GET / HTTP/1.1\r\n\r\n")
        }
    }

    @Test("rejects an HTTP/1.1 request with multiple Host headers (RFC 9110 §7.2)")
    func rejectsMultipleHosts() {
        #expect(throws: HTTP1ParseError.invalidHost) {
            try parse("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")
        }
    }

    @Test("rejects an invalid Content-Length (RFC 9112 §6.3)")
    func rejectsInvalidContentLength() {
        #expect(throws: HTTP1ParseError.invalidContentLength) {
            try parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n")
        }
    }

    @Test("rejects an unsupported Transfer-Encoding (RFC 9112 §6.1)")
    func rejectsUnsupportedTransferEncoding() {
        #expect(throws: HTTP1ParseError.unsupportedTransferEncoding) {
            try parse("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n")
        }
    }

    @Test(
        "rejects Transfer-Encoding on an HTTP/1.0 request (smuggling, RFC 9112 §6.1; audit H1-F5)")
    func rejectsTransferEncodingOnHTTP10() {
        // chunked is an HTTP/1.1 feature; honoring it on a 1.0 message is a desync vector.
        #expect(throws: HTTP1ParseError.unsupportedTransferEncoding) {
            try parse(
                "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        }
    }

    @Test("accepts case-insensitive 'chunked' transfer-coding (RFC 9112 §7)")
    func acceptsCaseInsensitiveChunked() throws {
        let parsed = try parse(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: Chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        )
        #expect(String(decoding: parsed.body, as: UTF8.self) == "hello")
    }

    @Test("rejects a request-line over the configured limit before materializing it (→ 414)")
    func rejectsLongRequestLine() {
        let limits = HTTPLimits(maxRequestLineLength: 16)
        #expect(throws: HTTP1ParseError.requestLineTooLong) {
            try parse("GET /way-too-long-target HTTP/1.1\r\nHost: x\r\n\r\n", limits: limits)
        }
    }
}
