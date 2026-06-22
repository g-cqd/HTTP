//
//  ChunkedBodyDecoderTests.swift
//  HTTP1Tests
//
//  Audit H1-F1/F2/F3 — the resumable chunked decoder: it decodes a body delivered in many small reads
//  correctly and incrementally (each octet consumed once, no O(n²) re-scan), bounds the cumulative
//  chunk-extension length (§7.1.1), and validates trailer field-lines like header lines (§7.1.2).
//

import HTTPCore
import Testing

@testable import HTTP1

@Suite("RFC 9112 §7.1 — resumable chunked decoder")
struct ChunkedBodyDecoderTests {

    /// Feeds `wire` one octet at a time, resuming the decoder after each, and returns the decoded body.
    /// `consumed` only ever advances (the decoder never re-reads a consumed octet), which is what keeps
    /// the cost O(n) rather than O(n²) across reads.
    private func decodeOneByteAtATime(
        _ wire: [UInt8], limits: HTTPLimits = .default
    ) throws -> [UInt8] {
        var state = ChunkedBodyDecoder.State()
        var body = [UInt8]()
        var buffer = [UInt8]()
        var consumed = 0
        for byte in wire {
            buffer.append(byte)
            let done = try buffer.withUnsafeBytes { raw -> Bool in
                var reader = ByteReader(raw, startingAt: consumed)
                let complete = try ChunkedBodyDecoder.advance(
                    &reader, state: &state, into: &body, limits: limits)
                #expect(reader.position >= consumed)  // never rewinds past already-consumed octets
                consumed = reader.position
                return complete
            }
            if done { break }
        }
        #expect(state.isComplete)
        return body
    }

    @Test("decodes a body delivered one octet per read (audit H1-F1)")
    func decodesByteByByte() throws {
        let wire = Array("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".utf8)
        #expect(try decodeOneByteAtATime(wire) == Array("hello world".utf8))
    }

    @Test("resumes mid-chunk so a large chunk in many reads is decoded once (audit H1-F1)")
    func resumesMidChunk() throws {
        let payload = String(repeating: "A", count: 1000)
        let wire = Array("3e8\r\n\(payload)\r\n0\r\n\r\n".utf8)  // 0x3e8 == 1000
        #expect(try decodeOneByteAtATime(wire) == Array(payload.utf8))
    }

    /// One-shot decode (the whole body present) — shares the resumable engine, so it exercises the same
    /// extension/trailer hardening on a single buffer.
    private func decodeWhole(_ string: String, limits: HTTPLimits = .default) throws -> [UInt8] {
        let bytes = Array(string.utf8)
        return try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            return try ChunkedDecoder.decode(&reader, limits: limits)
        }
    }

    @Test("bounds the cumulative chunk-extension length (audit H1-F2, RFC 9112 §7.1.1)")
    func boundsChunkExtension() {
        let limits = HTTPLimits(maxHeaderListSize: 8)  // tiny ancillary-metadata budget
        #expect(throws: HTTP1ParseError.chunkExtensionTooLarge) {
            _ = try decodeWhole("1;name=aaaaaaaaaa\r\nA\r\n0\r\n\r\n", limits: limits)
        }
    }

    @Test(
        "rejects a malformed trailer field-line (audit H1-F3, RFC 9112 §7.1.2)",
        arguments: [
            // A non-token field-name (embedded space).
            ("0\r\nBad Name: x\r\n\r\n", HTTP1ParseError.invalidFieldName),
            // Obsolete line folding — a trailer line that begins with whitespace.
            ("0\r\n folded\r\n\r\n", .obsoleteLineFolding),
            // A field-value carrying a control octet (NUL).
            ("0\r\nX-T: a\u{00}b\r\n\r\n", .invalidFieldValue),
        ])
    func rejectsMalformedTrailer(_ testCase: (wire: String, error: HTTP1ParseError)) {
        #expect(throws: testCase.error) { _ = try decodeWhole(testCase.wire) }
    }

    @Test("accepts a well-formed trailer field-line")
    func acceptsValidTrailer() throws {
        #expect(
            try decodeWhole("5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n") == Array("hello".utf8))
    }
}
