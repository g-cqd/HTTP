//
//  RequestBodyFormTests.swift
//  HTTPServerTests
//
//  Phase 2.2 — the ``RequestBody`` form-decoding conveniences: `application/x-www-form-urlencoded` via
//  ``QueryParameters`` and `multipart/form-data` (RFC 7578) using the boundary from the request's
//  Content-Type. They collect the body, then parse with the zero-dependency HTTPCore parsers.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Phase 2.2 — RequestBody form decoding")
struct RequestBodyFormTests {
    @Test("urlEncodedForm decodes a collected x-www-form-urlencoded body")
    func urlEncoded() async {
        let form = await RequestBody.collected(Array("a=1&b=hello+world".utf8)).urlEncodedForm()
        #expect(form["a"] == "1")
        #expect(form["b"] == "hello world")
    }

    @Test("multipartForm decodes using the boundary from the request's Content-Type")
    func multipart() async {
        let wire = ["--X", #"Content-Disposition: form-data; name="f""#, "", "v", "--X--", ""]
            .joined(separator: "\r\n")
        var fields = HTTPFields()
        _ = fields.setValue("multipart/form-data; boundary=X", for: .contentType)
        let request = HTTPRequest(method: .post, path: "/upload", headerFields: fields)
        let form = await RequestBody.collected(Array(wire.utf8)).multipartForm(for: request)
        #expect(form?["f"]?.body == Array("v".utf8))
    }

    @Test("multipartForm returns nil for a non-multipart request")
    func nonMultipart() async {
        let request = HTTPRequest(method: .post, path: "/upload")
        let form = await RequestBody.collected([]).multipartForm(for: request)
        #expect(form == nil)
    }
}
