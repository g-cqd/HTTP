//
//  ChunkedDecoderTests.swift
//  HTTP1Tests
//
//  RED→GREEN driver for RFC 9112 §7.1 chunked transfer-coding decoding.
//

import HTTPCore
import Testing

@testable import HTTP1

@Suite("RFC 9112 §7.1 — chunked transfer-coding")
struct ChunkedDecoderTests {
    private func decode(_ string: String, limits: HTTPLimits = .default) throws -> [UInt8] {
        let bytes = Array(string.utf8)
        return try bytes.withUnsafeBytes { raw -> [UInt8] in
            var reader = ByteReader(raw)
            return try ChunkedDecoder.decode(&reader, limits: limits)
        }
    }

    private func decodeString(_ string: String, limits: HTTPLimits = .default) throws -> String {
        String(decoding: try decode(string, limits: limits), as: UTF8.self)
    }

    @Test("decodes a single chunk")
    func singleChunk() throws {
        #expect(try decodeString("5\r\nhello\r\n0\r\n\r\n") == "hello")
    }

    @Test("decodes multiple chunks in order")
    func multipleChunks() throws {
        #expect(try decodeString("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n") == "hello world")
    }

    @Test("decodes an immediate last-chunk as an empty body")
    func emptyBody() throws {
        #expect(try decode("0\r\n\r\n").isEmpty)
    }

    @Test("ignores chunk extensions (RFC 9112 §7.1.1)")
    func chunkExtensions() throws {
        #expect(try decodeString("5;name=value\r\nhello\r\n0\r\n\r\n") == "hello")
    }

    @Test("reads hexadecimal chunk sizes")
    func hexadecimalSize() throws {
        #expect(try decodeString("10\r\n0123456789abcdef\r\n0\r\n\r\n") == "0123456789abcdef")
    }

    @Test("skips trailer fields after the last chunk")
    func trailerFields() throws {
        #expect(try decodeString("5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n") == "hello")
    }

    @Test(
        "rejects an invalid chunk size (RFC 9112 §7.1)",
        arguments: ["XY\r\nhi\r\n0\r\n\r\n", "\r\ndata\r\n0\r\n\r\n"]
    )
    func rejectsInvalidSize(_ input: String) {
        #expect(throws: HTTP1ParseError.invalidChunkSize) { _ = try decode(input) }
    }

    @Test("rejects missing CRLF after chunk data")
    func rejectsMissingCRLF() {
        #expect(throws: HTTP1ParseError.malformedChunk) { _ = try decode("5\r\nhelloXX0\r\n\r\n") }
    }

    @Test("enforces the maximum body size (→ 413)")
    func enforcesBodySize() {
        let limits = HTTPLimits(maxBodySize: 4)
        #expect(throws: HTTP1ParseError.bodyTooLarge) {
            _ = try decode("5\r\nhello\r\n0\r\n\r\n", limits: limits)
        }
    }

    @Test("rejects an overflowing chunk size without trapping (RFC 9112 §7.1)")
    func rejectsOverflowingChunkSize() {
        // After a non-empty chunk, a chunk-size of Int.max must fail closed as bodyTooLarge —
        // never overflow `body.count + size`.
        #expect(throws: HTTP1ParseError.bodyTooLarge) {
            _ = try decode("1\r\nA\r\n7fffffffffffffff\r\nx\r\n0\r\n\r\n")
        }
    }
}
