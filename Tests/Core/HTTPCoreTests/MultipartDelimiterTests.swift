//
//  MultipartDelimiterTests.swift
//  HTTPCoreTests
//
//  RFC 2046 §5.1.1 — the `multipart` delimiter grammar, adversarially. A delimiter is
//  `CRLF "--" boundary` followed ONLY by transport padding (LWSP) and CRLF, or by `--` for the
//  close-delimiter. Anything else is ordinary part content. Accepting a junk suffix such as
//  `\r\n--boundaryJUNK\r\n` lets an uploader forge a part split inside their own file bytes and smuggle
//  a second `Content-Disposition` past any content inspection (CWE-444, inconsistent interpretation of
//  an HTTP request). The boundary itself is `0*69<bchars> bcharsnospace`: 1–70 characters from a closed
//  ASCII set, never ending in a space (CWE-1284, improper validation of a specified quantity in input).
//

import Testing

@testable import HTTPCore

/// Joins `lines` with the CRLF that RFC 2046 requires between a body's structural lines.
private func wire(_ lines: [String]) -> [UInt8] {
    Array(lines.joined(separator: "\r\n").utf8)
}

/// A single-part body named `f` carrying `content`, framed by `boundary`, with a trailing CRLF.
private func framed(_ boundary: String, content: String = "v") -> [UInt8] {
    wire([
        "--" + boundary,
        #"Content-Disposition: form-data; name="f""#,
        "",
        content,
        "--" + boundary + "--",
        ""
    ])
}

@Test("a junk suffix after the boundary is not a delimiter and does not split the part")
func junkDelimiterSuffixDoesNotSplit() {
    let body = wire([
        "--B",
        #"Content-Disposition: form-data; name="f"; filename="a.bin""#,
        "",
        "before",
        "--BJUNK",
        "after",
        "--B--",
        ""
    ])
    let form = MultipartFormData.parse(body, boundary: "B")
    #expect(form?.parts.count == 1)
    #expect(form?["f"]?.body == Array("before\r\n--BJUNK\r\nafter".utf8))
}

@Test("a boundary that is only a prefix of the delimiter line is not a delimiter either")
func longerBoundaryPrefixIsNotADelimiter() {
    let body = wire([
        "--B",
        #"Content-Disposition: form-data; name="f""#,
        "",
        "one",
        "--BB",
        "--B--",
        ""
    ])
    let form = MultipartFormData.parse(body, boundary: "B")
    #expect(form?["f"]?.body == Array("one\r\n--BB".utf8))
}

@Test(
    "transport padding between the boundary and its CRLF is accepted (RFC 2046 §5.1.1)",
    arguments: ["", " ", "\t", " \t "]
)
func transportPaddingIsAccepted(_ padding: String) {
    let body = wire([
        "--B" + padding,
        #"Content-Disposition: form-data; name="f""#,
        "",
        "v",
        "--B--" + padding,
        ""
    ])
    #expect(MultipartFormData.parse(body, boundary: "B")?["f"]?.body == Array("v".utf8))
}

@Test("a close-delimiter may end the body with no epilogue and therefore no trailing CRLF")
func closeDelimiterAtEndOfBody() {
    let body = wire(["--B", #"Content-Disposition: form-data; name="f""#, "", "v", "--B--"])
    #expect(MultipartFormData.parse(body, boundary: "B")?["f"]?.body == Array("v".utf8))
}

@Test("a preamble before the first delimiter is ignored, and an epilogue after the last one too")
func preambleAndEpilogueAreIgnored() {
    let body = wire([
        "this preamble is not a part",
        "--B",
        #"Content-Disposition: form-data; name="f""#,
        "",
        "v",
        "--B--",
        "this epilogue is not a part either"
    ])
    let form = MultipartFormData.parse(body, boundary: "B")
    #expect(form?.parts.count == 1)
    #expect(form?["f"]?.body == Array("v".utf8))
}

/// The unterminated tails that must never be read as a close-delimiter.
private let truncatedTails = ["--B", "--B-", ""]

@Test(
    "a truncated or absent closing delimiter is rejected, never treated as closing",
    arguments: truncatedTails
)
func truncatedClosingDelimiterIsRejected(_ tail: String) {
    var lines = ["--B", #"Content-Disposition: form-data; name="f""#, "", "v"]
    if !tail.isEmpty {
        lines.append(tail)
    }
    #expect(MultipartFormData.parse(wire(lines), boundary: "B") == nil)
}

@Test("the boundary token inside a part body, not at a line start, does not split it")
func boundaryInsidePartBody() {
    let form = MultipartFormData.parse(framed("B", content: "data--Bmore"), boundary: "B")
    #expect(form?["f"]?.body == Array("data--Bmore".utf8))
}

@Test("an empty part body is retained as zero bytes rather than dropped")
func emptyPartBodyIsRetained() {
    let body = wire([
        "--B",
        #"Content-Disposition: form-data; name="empty""#,
        "",
        "",
        "--B",
        #"Content-Disposition: form-data; name="after""#,
        "",
        "x",
        "--B--",
        ""
    ])
    let form = MultipartFormData.parse(body, boundary: "B")
    #expect(form?.parts.count == 2)
    #expect(form?["empty"]?.body.isEmpty == true)
    #expect(form?["after"]?.body == Array("x".utf8))
}

@Test(
    "a boundary outside the RFC 2046 §5.1.1 grammar is rejected before any scanning",
    arguments: ["", #"a"b"#, "a;b", "a\rb", "a\nb", "trailing ", "café", "a%b", "a@b"]
)
func invalidBoundaryIsRejected(_ boundary: String) {
    #expect(MultipartFormData.parse(framed(boundary), boundary: boundary) == nil)
}

@Test("a boundary longer than the RFC 2046 §5.1.1 cap of 70 characters is rejected")
func overlongBoundaryIsRejected() {
    let atCap = String(repeating: "a", count: 70)
    let overCap = String(repeating: "a", count: 71)
    #expect(MultipartFormData.parse(framed(atCap), boundary: atCap)?["f"]?.body == Array("v".utf8))
    #expect(MultipartFormData.parse(framed(overCap), boundary: overCap) == nil)
}

@Test("every bchars character is accepted inside a boundary (RFC 2046 §5.1.1)")
func fullBoundaryCharacterSetIsAccepted() {
    let boundary = "aZ09'()+_,-./:=? x"
    let form = MultipartFormData.parse(framed(boundary), boundary: boundary)
    #expect(form?["f"]?.body == Array("v".utf8))
}
