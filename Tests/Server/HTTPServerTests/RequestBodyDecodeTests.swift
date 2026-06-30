//
//  RequestBodyDecodeTests.swift
//  HTTPServerTests
//
//  Phase 2.3 — the typed body-codec conveniences: ``RequestBody/decode(using:for:)`` plugs a decoder
//  (passing the request's content type) and ``ServerResponse/encoded(_:using:status:)`` builds a response
//  from a typed value through a ``BodyEncoder``.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Phase 2.3 — RequestBody.decode / ServerResponse.encoded")
struct RequestBodyDecodeTests {
    @Test("decode(using:for:) decodes a form body via the seam")
    func decodeForm() async throws {
        let request = HTTPRequest(method: .post, path: "/")
        let form = try await RequestBody.collected(Array("x=1&y=2".utf8))
            .decode(using: FormURLEncodedDecoder(), for: request)
        #expect(form["x"] == "1")
        #expect(form["y"] == "2")
    }

    @Test("decode(using:for:) decodes multipart using the request's content type")
    func decodeMultipart() async throws {
        var fields = HTTPFields()
        _ = fields.setValue("multipart/form-data; boundary=B", for: .contentType)
        let request = HTTPRequest(method: .post, path: "/upload", headerFields: fields)
        let wire = ["--B", #"Content-Disposition: form-data; name="f""#, "", "v", "--B--", ""]
            .joined(separator: "\r\n")
        let form = try await RequestBody.collected(Array(wire.utf8))
            .decode(using: MultipartFormDecoder(), for: request)
        #expect(form["f"]?.body == Array("v".utf8))
    }

    @Test("ServerResponse.encoded uses the encoder's content type and bytes")
    func encoded() throws {
        let response = try ServerResponse.encoded("hi", using: ShoutEncoder())
        #expect(response.head.headerFields[.contentType] == "text/plain; charset=utf-8")
        #expect(response.body == Array("HI".utf8))
    }

    /// A trivial ``BodyEncoder`` for the test — upcases text.
    private struct ShoutEncoder: BodyEncoder {
        let contentType = "text/plain; charset=utf-8"

        func encode(_ value: String) -> [UInt8] {
            Array(value.uppercased().utf8)
        }
    }
}
