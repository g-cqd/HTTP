//
//  BodyCodecTests.swift
//  HTTPCoreTests
//
//  Phase 2.3 — the shipped ``BodyDecoder`` conformers: form-urlencoded decoding (lenient), and multipart
//  decoding driven by the boundary in the content type, including its error cases.
//

import Testing

@testable import HTTPCore

@Suite("Phase 2.3 — body-codec seam")
struct BodyCodecTests {
    @Test("FormURLEncodedDecoder decodes form fields")
    func formDecoder() {
        let form = FormURLEncodedDecoder().decode(Array("a=1&b=x+y".utf8), contentType: nil)
        #expect(form["a"] == "1")
        #expect(form["b"] == "x y")
    }

    @Test("MultipartFormDecoder decodes using the boundary from the content type")
    func multipartDecoder() throws {
        let wire = ["--B", #"Content-Disposition: form-data; name="f""#, "", "v", "--B--", ""]
            .joined(separator: "\r\n")
        let form = try MultipartFormDecoder()
            .decode(
                Array(wire.utf8), contentType: "multipart/form-data; boundary=B"
            )
        #expect(form["f"]?.body == Array("v".utf8))
    }

    @Test("MultipartFormDecoder throws unsupportedContentType without a boundary")
    func multipartNoBoundary() {
        #expect(throws: BodyDecodingError.unsupportedContentType) {
            try MultipartFormDecoder().decode([], contentType: "application/json")
        }
    }

    @Test("MultipartFormDecoder throws malformed for a garbage body")
    func multipartMalformed() {
        #expect(throws: BodyDecodingError.malformed) {
            try MultipartFormDecoder()
                .decode(
                    Array("garbage".utf8), contentType: "multipart/form-data; boundary=B"
                )
        }
    }
}
