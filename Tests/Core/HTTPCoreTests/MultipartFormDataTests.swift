//
//  MultipartFormDataTests.swift
//  HTTPCoreTests
//
//  RFC 7578 — `multipart/form-data` parsing: split a body on its `--boundary` delimiter into parts, each
//  with a `Content-Disposition` name (and optional filename / `Content-Type`) and raw bytes. The parser
//  is lenient and trap-free — malformed input returns `nil`, never crashes.
//

import Testing

@testable import HTTPCore

@Suite("RFC 7578 — multipart/form-data")
struct MultipartFormDataTests {
    /// Joins `lines` with CRLF (the line ending RFC 7578 / RFC 2046 require) into a body.
    private func body(_ lines: [String]) -> [UInt8] {
        Array(lines.joined(separator: "\r\n").utf8)
    }

    /// The boundary parsed from a `Content-Type` value (shortens the assertions below).
    private func boundary(_ contentType: String) -> String? {
        MultipartFormData.boundary(ofContentType: contentType)
    }

    @Test("parses a text field and a file part (name, filename, content-type, body)")
    func parsesFieldAndFile() {
        let wire = body([
            "--BOUNDARY",
            #"Content-Disposition: form-data; name="field""#,
            "",
            "value",
            "--BOUNDARY",
            #"Content-Disposition: form-data; name="file"; filename="a.txt""#,
            "Content-Type: text/plain",
            "",
            "file contents",
            "--BOUNDARY--",
            ""
        ])
        let form = MultipartFormData.parse(wire, boundary: "BOUNDARY")
        #expect(form?["field"]?.body == Array("value".utf8))
        #expect(form?["field"]?.filename == nil)
        #expect(form?["file"]?.filename == "a.txt")
        #expect(form?["file"]?.contentType == "text/plain")
        #expect(
            String(decoding: form?["file"]?.body ?? [], as: Unicode.UTF8.self) == "file contents"
        )
    }

    @Test("preserves binary body bytes exactly, including an embedded CRLF")
    func preservesBinaryBody() {
        let payload: [UInt8] = [0x00, 0x0D, 0x0A, 0xFF, 0x42]
        var wire = body([
            "--B",
            #"Content-Disposition: form-data; name="blob"; filename="b.bin""#,
            "",
            ""
        ])
        wire += payload
        wire += body(["", "--B--", ""])
        let form = MultipartFormData.parse(wire, boundary: "B")
        #expect(form?["blob"]?.body == payload)
    }

    @Test("repeated field names are all retained, in order")
    func repeatedFields() {
        let wire = body([
            "--B",
            #"Content-Disposition: form-data; name="tag""#,
            "",
            "a",
            "--B",
            #"Content-Disposition: form-data; name="tag""#,
            "",
            "b",
            "--B--",
            ""
        ])
        let form = MultipartFormData.parse(wire, boundary: "B")
        let bodies = form?.all("tag").map { String(decoding: $0.body, as: Unicode.UTF8.self) }
        #expect(bodies == ["a", "b"])
    }

    @Test("reads the boundary from a Content-Type value, quoted or bare (RFC 7578 §4.1)")
    func boundaryFromContentType() {
        #expect(boundary("multipart/form-data; boundary=xyz") == "xyz")
        #expect(boundary(#"multipart/form-data; boundary="a b""#) == "a b")
        #expect(boundary("application/json") == nil)
    }

    @Test("a body with no valid delimiter is nil, never trapping (lenient)")
    func malformedIsNil() {
        #expect(MultipartFormData.parse(Array("not multipart at all".utf8), boundary: "B") == nil)
        #expect(MultipartFormData.parse([], boundary: "B") == nil)
    }
}
