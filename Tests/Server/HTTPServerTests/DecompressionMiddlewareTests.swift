//
//  DecompressionMiddlewareTests.swift
//  HTTPServerTests
//
//  RFC 9110 §8.4 — inbound decompression (gzip, deflate, Brotli) with a decompression-bomb cap
//  (CWE-409). The middleware round-trips a coded body to the responder as identity (Content-Encoding
//  stripped), leaves an unsupported / absent encoding untouched, and fails closed with 413 on a
//  malformed member, an over-ratio body, or one past the absolute cap — never buffering a bomb. The
//  responder echoes what it received (body and request headers) so each test inspects the returned
//  response to see what reached the responder.
//

import Compression
import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — inbound decompression, bomb-hardened (RFC 9110 §8.4, CWE-409)")
struct DecompressionMiddlewareTests {
    private let echo = ClosureResponder { request, body, _ in
        ServerResponse(
            HTTPResponse(status: .ok, headerFields: request.headerFields),
            body: await body.collect()
        )
    }

    private func request(encoding: String?) -> HTTPRequest {
        var fields = HTTPFields()
        if let encoding {
            _ = fields.append(encoding, for: .contentEncoding)
        }
        return HTTPRequest(
            method: .post, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }

    /// Runs the middleware (with the given caps) over `body` carrying `encoding`, returning what reached
    /// the echo responder.
    private func respond(
        _ encoding: String?,
        _ body: [UInt8],
        ratio: Int = HTTPLimits.default.maxDecompressionRatio,
        maxSize: Int = HTTPLimits.default.maxDecompressedBodySize
    ) async -> ServerResponse {
        let middleware = DecompressionMiddleware(maxDecompressedSize: maxSize, maxRatio: ratio)
        return await middleware.respond(to: request(encoding: encoding), body: body, next: echo)
    }

    @Test("a gzip body is decompressed to identity, and Content-Encoding is stripped")
    func decompressesGzip() async {
        let original = Array(String(repeating: "decompression test. ", count: 50).utf8)
        // A generous ratio so this (compressible) body is not itself rejected — the caps are exercised
        // by the bomb cases below.
        let response = await respond("gzip", Gzip.compress(original) ?? [], ratio: 1_000)
        #expect(response.body == original)
        #expect(response.head.headerFields[.contentEncoding] == nil)
        #expect(response.head.headerFields[.contentLength] == String(original.count))
    }

    @Test("an unsupported Content-Encoding is left untouched for the responder")
    func unsupportedEncodingPassesThrough() async {
        let body = Array("zstd-or-whatever".utf8)
        let response = await respond("zstd", body)
        #expect(response.body == body)
        #expect(response.head.headerFields[.contentEncoding] == "zstd")
    }

    @Test("a raw deflate body is decompressed to identity (RFC 1951)")
    func decompressesDeflate() async {
        let original = Array(String(repeating: "deflate test. ", count: 50).utf8)
        let coded = compress(original, using: COMPRESSION_ZLIB)
        let response = await respond("deflate", coded, ratio: 1_000)
        #expect(response.body == original)
        #expect(response.head.headerFields[.contentEncoding] == nil)
    }

    @Test("a Brotli body is decompressed to identity (RFC 7932)")
    func decompressesBrotli() async {
        let original = Array(String(repeating: "brotli test. ", count: 50).utf8)
        let coded = compress(original, using: COMPRESSION_BROTLI)
        let response = await respond("br", coded, ratio: 1_000)
        #expect(response.body == original)
        #expect(response.head.headerFields[.contentEncoding] == nil)
    }

    @Test("a gzip member carrying a name (FLG set) still decodes (RFC 1952 §2.3.1)")
    func decompressesGzipWithName() async throws {
        let original = Array("named gzip member".utf8)
        let plain = try #require(Gzip.compress(original))
        var named = Array(plain[0 ..< 10])
        named[3] = 0x08  // FLG = FNAME
        named.append(contentsOf: Array("file.txt".utf8))
        named.append(0)
        named.append(contentsOf: plain[10...])
        #expect(await respond("gzip", named, ratio: 1_000).body == original)
    }

    @Test("a gzip member with a corrupt CRC is rejected, not mis-decoded (RFC 1952)")
    func rejectsCorruptGzipCRC() async throws {
        let original = Array("integrity matters".utf8)
        var corrupt = try #require(Gzip.compress(original))
        corrupt[corrupt.count - 8] ^= 0xff  // flip a CRC-32 trailer byte
        #expect(await respond("gzip", corrupt, ratio: 1_000).head.status == .contentTooLarge)
    }

    @Test("a body with no Content-Encoding is left untouched")
    func noEncodingPassesThrough() async {
        let body = Array("plain identity body".utf8)
        #expect(await respond(nil, body).body == body)
    }

    @Test("an empty gzip-labelled body passes straight through")
    func emptyBodyPassesThrough() async {
        let response = await respond("gzip", [])
        #expect(response.body.isEmpty)
        #expect(response.head.status == .ok)
    }

    @Test("a highly-compressible body over the ratio cap is 413, not a buffered bomb")
    func bombOverRatioRejected() async {
        let gzipped = Gzip.compress([UInt8](repeating: 0, count: 100_000)) ?? []
        #expect(await respond("gzip", gzipped).head.status == .contentTooLarge)
    }

    @Test("a body past the absolute decompressed-size cap is 413")
    func bombOverAbsoluteCapRejected() async {
        let gzipped = Gzip.compress([UInt8](repeating: 0x41, count: 4_096)) ?? []
        let response = await respond("gzip", gzipped, ratio: 1_000_000, maxSize: 64)
        #expect(response.head.status == .contentTooLarge)
    }

    @Test("a malformed gzip member (bad magic) is 413, never mis-decoded")
    func malformedGzipRejected() async {
        let response = await respond("gzip", Array("not a gzip member at all".utf8))
        #expect(response.head.status == .contentTooLarge)
    }

    /// Compresses `input` with a Compression-framework `algorithm` (raw DEFLATE for `COMPRESSION_ZLIB`,
    /// a Brotli stream for `COMPRESSION_BROTLI`) — the test mirror of the production decoders' input.
    private func compress(_ input: [UInt8], using algorithm: compression_algorithm) -> [UInt8] {
        let capacity = input.count + input.count / 2 + 128
        var destination = [UInt8](repeating: 0, count: capacity)
        let written = input.withUnsafeBufferPointer { source -> Int in
            destination.withUnsafeMutableBufferPointer { output -> Int in
                guard let source = source.baseAddress, let output = output.baseAddress else {
                    return 0
                }
                return compression_encode_buffer(
                    output, capacity, source, input.count, nil, algorithm
                )
            }
        }
        destination.removeLast(destination.count - written)
        return destination
    }
}
