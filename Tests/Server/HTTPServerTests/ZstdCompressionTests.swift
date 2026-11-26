//
//  ZstdCompressionTests.swift
//  HTTPServerTests
//
//  RFC 8878 `zstd` content coding (the vendored libzstd, `HTTPZstd`). Mirrors
//  ``CompressionMiddlewareTests``: a zstd round-trip (encode, then decode with the library's decoder to
//  prove the produced frame is faithful) plus the negotiation edges that involve zstd — it is chosen
//  ahead of gzip when accepted at the top quality, beaten by Brotli on a tie (the server preference
//  br > zstd > gzip, RFC 9110 §12.5.3), and refused at `q=0`.
//

import HTTPCore
import HTTPZstd
import Testing

@testable import HTTPServer

@Suite("Middleware — zstd content coding (RFC 8878)")
struct ZstdCompressionTests {
    @Test("compresses a large body when the client accepts zstd")
    func compresses() async {
        let body = Array(String(repeating: "swift http server ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("zstd"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "zstd")
        #expect(response.body.count < body.count)
        #expect(response.head.headerFields[.contentLength] == String(response.body.count))
        #expect(
            response.head.headerFields[.vary]?.lowercased().contains("accept-encoding") == true
        )
        // The zstd frame magic number (RFC 8878 §3.1.1): 0xFD2FB528, little-endian on the wire.
        #expect(Array(response.body.prefix(4)) == [0x28, 0xb5, 0x2f, 0xfd])
    }

    @Test("the zstd frame decodes back to the original (RFC 8878 round-trip)")
    func roundTrips() throws {
        let body = Array(String(repeating: "round trip payload ", count: 300).utf8)
        let frame = try #require(ZstdEncoder().encode(body))
        #expect(unzstd(frame) == body)
    }

    @Test("zstd is chosen ahead of gzip at the top quality (server preference)")
    func chosenAtHigherQuality() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body)
            .respond(to: get("br;q=0.5, zstd;q=1.0, gzip;q=0.5"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "zstd")
    }

    @Test("Brotli beats zstd on an equal-quality tie where it encodes (RFC 9110 §12.5.3)")
    func brotliBeatsZstdOnTie() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("zstd, br"), body: [])
        // zstd is on every build; `br` only where a Brotli backend is (Darwin, or the Linux `Brotli` trait).
        let brotli = BrotliEncoder().encode(body) != nil
        #expect(response.head.headerFields[.contentEncoding] == (brotli ? "br" : "zstd"))
    }

    @Test("zstd;q=0 refuses zstd and falls back to gzip (RFC 9110 §12.5.3)")
    func refusedAtQualityZero() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let response = await wrapped(body).respond(to: get("zstd;q=0, gzip"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "gzip")
    }

    // MARK: Helpers

    private func wrapped(
        _ body: [UInt8],
        contentType: String = "text/plain"
    ) -> any HTTPResponder {
        ClosureResponder { _, _, _ in
            var fields = HTTPFields()
            _ = fields.append(contentType, for: .contentType)
            return ServerResponse(HTTPResponse(status: .ok, headerFields: fields), body: body)
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

    /// Decodes a zstd frame with the vendored library's decoder — the symmetric check of ``ZstdEncoder``.
    private func unzstd(_ frame: [UInt8]) -> [UInt8] {
        (try? Zstd.decompress(frame, maxOutputSize: 1 << 24)) ?? []
    }
}
