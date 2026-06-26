//
//  CompressionMiddlewareTests.swift
//  HTTPServerTests
//
//  Content coding (RFC 9110 §8.4.1 / §12.5.3): the client's preferred coding is chosen from
//  `Accept-Encoding` by q-value (preferring `br` over `gzip` on a tie), the body is encoded, and the
//  member round-trips back to the original — gzip (RFC 1952) and Brotli (RFC 7932). Negotiation edge
//  cases (q=0 refusal, the `*` wildcard, identity) and the streaming-response skip are covered too.
//

import Compression
import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — content coding (gzip + Brotli)")
struct CompressionMiddlewareTests {
    @Test("compresses a large body when the client accepts gzip")
    func compresses() async {
        let body = Array(String(repeating: "swift http server ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("gzip"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "gzip")
        #expect(response.body.count < body.count)
        #expect(response.head.headerFields[.contentLength] == String(response.body.count))
        #expect(response.head.headerFields[.vary]?.lowercased().contains("accept-encoding") == true)
        #expect(Array(response.body.prefix(3)) == [0x1f, 0x8b, 0x08])  // gzip magic + deflate
    }

    @Test("the gzip member decodes back to the original (RFC 1952 round-trip)")
    func roundTrips() throws {
        let body = Array(String(repeating: "round trip payload ", count: 300).utf8)
        let gzipped = try #require(Gzip.compress(body))
        #expect(gunzip(gzipped) == body)
        // The trailing ISIZE is the original length mod 2^32 (RFC 1952 §2.3.1).
        let isize = gzipped.suffix(4)
        let size = isize.reversed().reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        #expect(size == UInt32(body.count))
    }

    @Test("compresses with Brotli when the client accepts br (RFC 7932 round-trip)")
    func compressesBrotli() async {
        let body = Array(String(repeating: "swift http server ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("br"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "br")
        #expect(response.body.count < body.count)
        #expect(response.head.headerFields[.contentLength] == String(response.body.count))
        #expect(response.head.headerFields[.vary]?.lowercased().contains("accept-encoding") == true)
        #expect(debrotli(response.body) == body)  // the level-2 encoder's output decodes faithfully
    }

    @Test("prefers Brotli over gzip at equal quality (RFC 9110 §12.5.3 server preference)")
    func prefersBrotliOnTie() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("gzip, br"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "br")
    }

    @Test("a higher q-value wins over the server preference (gzip beats br;q=0.5)")
    func qualityWinsOverPreference() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("br;q=0.5, gzip;q=1.0"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "gzip")
    }

    @Test("br;q=0 refuses Brotli and falls back to gzip (RFC 9110 §12.5.3)")
    func brotliRefusedFallsBackToGzip() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("br;q=0, gzip"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "gzip")
    }

    @Test("the * wildcard selects the server's preferred coding (br)")
    func wildcardSelectsBrotli() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("*"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "br")
    }

    @Test("does not compress when the client omits Accept-Encoding")
    func skipsWithoutAcceptEncoding() async {
        let body = Array(String(repeating: "x", count: 4_096).utf8)
        let response = await wrapped(body).respond(to: get(nil), body: [])
        #expect(response.head.headerFields[.contentEncoding] == nil)
        #expect(response.body == body)
    }

    @Test("identity only serves the representation unencoded")
    func identityOnlyServesUnencoded() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("identity"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == nil)
        #expect(response.body == body)
    }

    @Test("every coding refused (q=0) serves the representation unencoded")
    func allCodingsRefusedServesUnencoded() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("gzip;q=0, br;q=0"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == nil)
        #expect(response.body == body)
    }

    @Test("does not compress bodies below the minimum size")
    func skipsSmall() async {
        let response = await wrapped(Array("tiny".utf8)).respond(to: get("gzip"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == nil)
    }

    @Test("does not compress already-compressed media types")
    func skipsIncompressible() async {
        let body = [UInt8](repeating: 7, count: 4_096)
        let response = await wrapped(body, contentType: "image/png")
            .respond(to: get("br, gzip"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == nil)
    }

    @Test("a streaming response is not compressed even when br is accepted")
    func skipsStreamingResponse() async {
        let response = await wrappedStreaming().respond(to: get("br"), body: [])
        #expect(response.stream != nil)
        #expect(response.head.headerFields[.contentEncoding] == nil)
    }

    @Test("honors gzip;q=0 as a refusal (RFC 9110 §12.5.3)")
    func honorsQualityZero() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("gzip;q=0"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == nil)
    }

    // MARK: Helpers

    private func wrapped(_ body: [UInt8], contentType: String = "text/plain") -> any HTTPResponder {
        ClosureResponder { _, _ in
            var fields = HTTPFields()
            _ = fields.append(contentType, for: .contentType)
            return ServerResponse(HTTPResponse(status: .ok, headerFields: fields), body: body)
        }
        .wrapped(by: CompressionMiddleware())
    }

    private func wrappedStreaming() -> any HTTPResponder {
        ClosureResponder { _, _ in
            var fields = HTTPFields()
            _ = fields.append("text/plain", for: .contentType)
            let payload = Array(String(repeating: "stream ", count: 512).utf8)
            let stream = ResponseStream(contentLength: payload.count) { writer in
                try await writer.write(payload)
            }
            return ServerResponse(HTTPResponse(status: .ok, headerFields: fields), stream: stream)
        }
        .wrapped(by: CompressionMiddleware())
    }

    private func get(_ acceptEncoding: String?) -> HTTPRequest {
        var fields = HTTPFields()
        if let acceptEncoding { _ = fields.append(acceptEncoding, for: .acceptEncoding) }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }

    /// Inflates a gzip member by stripping the 10-octet header and 8-octet trailer, then decoding the
    /// raw DEFLATE with the framework — the symmetric check of ``Gzip``.
    private func gunzip(_ gzip: [UInt8]) -> [UInt8] {
        let deflate = Array(gzip[10 ..< (gzip.count - 8)])
        var destination = [UInt8](repeating: 0, count: 1 << 20)
        let written = deflate.withUnsafeBufferPointer { source in
            destination.withUnsafeMutableBufferPointer { destination -> Int in
                guard let source = source.baseAddress, let destination = destination.baseAddress
                else { return 0 }
                return compression_decode_buffer(
                    destination, 1 << 20, source, deflate.count, nil, COMPRESSION_ZLIB
                )
            }
        }
        return Array(destination.prefix(written))
    }

    /// Decodes a raw Brotli stream with the framework — the symmetric check of ``Brotli``.
    private func debrotli(_ brotli: [UInt8]) -> [UInt8] {
        var destination = [UInt8](repeating: 0, count: 1 << 20)
        let written = brotli.withUnsafeBufferPointer { source in
            destination.withUnsafeMutableBufferPointer { destination -> Int in
                guard let source = source.baseAddress, let destination = destination.baseAddress
                else { return 0 }
                return compression_decode_buffer(
                    destination, 1 << 20, source, brotli.count, nil, COMPRESSION_BROTLI
                )
            }
        }
        return Array(destination.prefix(written))
    }
}
