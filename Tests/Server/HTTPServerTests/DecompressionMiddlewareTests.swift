//
//  DecompressionMiddlewareTests.swift
//  HTTPServerTests
//
//  RFC 9110 §8.4 — inbound gzip decompression with a decompression-bomb cap (CWE-409). The middleware
//  must round-trip a gzip body to the responder as identity (Content-Encoding stripped), leave a
//  non-gzip / absent encoding untouched, and fail closed with 413 on a malformed member, an over-ratio
//  body, or one past the absolute cap — never buffering a bomb. The responder echoes what it received
//  (the body as the response body, the request headers as the response headers) so each test inspects
//  the returned response to see what actually reached the responder.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — inbound decompression, bomb-hardened (RFC 9110 §8.4, CWE-409)")
struct DecompressionMiddlewareTests {
    private let echo = ClosureResponder { request, body in
        ServerResponse(HTTPResponse(status: .ok, headerFields: request.headerFields), body: body)
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

    @Test("a non-gzip Content-Encoding is left untouched for the responder")
    func nonGzipPassesThrough() async {
        let body = Array("brotli-or-whatever".utf8)
        let response = await respond("br", body)
        #expect(response.body == body)
        #expect(response.head.headerFields[.contentEncoding] == "br")
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
}
