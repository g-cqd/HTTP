//
//  ContentEncoderTests.swift
//  HTTPServerTests
//
//  Phase 3.3 — the pluggable content-coding seam: ``CompressionMiddleware`` negotiates over an injected
//  `[any ContentEncoder]`, so a consumer can add a custom coding or restrict the built-in set. The
//  built-in ``GzipEncoder`` / ``BrotliEncoder`` / ``ZstdEncoder`` name the standard codings.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Phase 3.3 — pluggable ContentEncoder")
struct ContentEncoderTests {
    /// A stand-in coding with a custom token and a fixed, tiny output — enough to prove the middleware
    /// negotiates and applies an injected encoder.
    private struct StubEncoder: ContentEncoder {
        let token = "x-stub"

        func encode(_ body: [UInt8]) -> [UInt8]? {
            Array(body.prefix(1))
        }
    }

    @Test("a custom encoder is negotiated and applied")
    func customEncoderApplied() async {
        let body = [UInt8](repeating: 0x61, count: 4_096)
        let responder = ClosureResponder { _, _, _ in
            var fields = HTTPFields()
            _ = fields.append("text/plain", for: .contentType)
            return ServerResponse(HTTPResponse(status: .ok, headerFields: fields), body: body)
        }
        .wrapped(by: CompressionMiddleware(encoders: [StubEncoder()]))
        let response = await responder.respond(to: get("x-stub"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "x-stub")
        #expect(response.body == Array(body.prefix(1)))
    }

    @Test("restricting the encoder list drops codings not offered (br absent from [gzip])")
    func restrictedEncoderList() async {
        let body = Array(String(repeating: "compressible text ", count: 256).utf8)
        let responder = ClosureResponder { _, _, _ in
            var fields = HTTPFields()
            _ = fields.append("text/plain", for: .contentType)
            return ServerResponse(HTTPResponse(status: .ok, headerFields: fields), body: body)
        }
        .wrapped(by: CompressionMiddleware(encoders: [GzipEncoder()]))
        let response = await responder.respond(to: get("br, gzip"), body: [])
        #expect(response.head.headerFields[.contentEncoding] == "gzip")
    }

    @Test("the built-in encoders name the standard codings")
    func builtInTokens() {
        #expect(GzipEncoder().token == "gzip")
        #expect(BrotliEncoder().token == "br")
        #expect(ZstdEncoder().token == "zstd")
    }

    @Test("GzipEncoder produces a gzip member")
    func gzipEncoderProducesGzip() {
        let body = Array(String(repeating: "round trip ", count: 256).utf8)
        let encoded = GzipEncoder().encode(body)
        let magic = Array((encoded ?? []).prefix(3))
        #expect(encoded != nil)
        #expect(magic == [0x1f, 0x8b, 0x08])  // gzip magic + deflate
    }

    private func get(_ acceptEncoding: String?) -> HTTPRequest {
        var fields = HTTPFields()
        if let acceptEncoding { _ = fields.append(acceptEncoding, for: .acceptEncoding) }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }
}
