//
//  MultipartParameterTests.swift
//  HTTPCoreTests
//
//  RFC 2045 §5.1 — the `; attribute=value` parameter list carried by `Content-Type` and
//  `Content-Disposition` (RFC 7578 §4.2), where `value := token / quoted-string` and a quoted-string
//  may contain any character, including `;` and (via `quoted-pair`) `"`. Splitting the list on every
//  semicolon truncates a legitimate `filename="a;b.txt"` and — worse — lets a crafted filename inject a
//  `name=` parameter that outranks the real one, so the parser and any component that reads the header
//  correctly disagree about which form field the upload belongs to (CWE-444).
//

import Testing

@testable import HTTPCore

/// The `Content-Disposition` value of a single part named `f`, framed into a parsable body.
private func disposition(_ value: String) -> MultipartFormData.Part? {
    let body = ["--B", "Content-Disposition: " + value, "", "v", "--B--", ""]
    return MultipartFormData.parse(Array(body.joined(separator: "\r\n").utf8), boundary: "B")?
        .parts.first
}

@Test("a semicolon inside a quoted filename is data, not a parameter separator (RFC 2045 §5.1)")
func quotedSemicolonIsNotASeparator() {
    let part = disposition(#"form-data; name="f"; filename="a;b.txt""#)
    #expect(part?.name == "f")
    #expect(part?.filename == "a;b.txt")
}

@Test("a name= parameter smuggled inside a quoted filename does not outrank the real one")
func smuggledParameterInsideQuotedValueIsIgnored() {
    let part = disposition(#"form-data; filename="x; name=\"evil\""; name="real""#)
    #expect(part?.name == "real")
    #expect(part?.filename == #"x; name="evil""#)
}

@Test("a quoted-pair escapes the character that follows it (RFC 2045 §5.1)")
func quotedPairIsUnescaped() {
    #expect(disposition(#"form-data; name="f"; filename="a\"b.txt""#)?.filename == #"a"b.txt"#)
    #expect(disposition(#"form-data; name="f"; filename="a\\b.txt""#)?.filename == #"a\b.txt"#)
}

@Test("an unterminated quoted value is read to the end of the header rather than dropped")
func unterminatedQuotedValueIsLenient() {
    #expect(disposition(#"form-data; name="f"; filename="abc"#)?.filename == "abc")
}

@Test("an unquoted token value ends at the next semicolon and is trimmed of LWSP")
func unquotedTokenValueIsTrimmed() {
    #expect(disposition("form-data; name = plain ; filename=x.txt")?.name == "plain")
    #expect(disposition("form-data; name = plain ; filename=x.txt")?.filename == "x.txt")
}

@Test("parameter attributes are matched case-insensitively (RFC 2045 §5.1)")
func attributeMatchIsCaseInsensitive() {
    #expect(disposition(#"form-data; NAME="f"; FileName="a.txt""#)?.filename == "a.txt")
}

@Test("an attribute that merely ends with the sought name does not match it")
func attributeSuffixDoesNotMatch() {
    #expect(disposition(#"form-data; xname="wrong"; name="right""#)?.name == "right")
    #expect(disposition(#"form-data; myfilename="wrong"; name="f""#)?.filename == nil)
}

@Test("an empty quoted value is an empty string, not an absent parameter")
func emptyQuotedValueIsEmpty() {
    #expect(disposition(#"form-data; name="f"; filename="""#)?.filename?.isEmpty == true)
}

@Test(
    "a Content-Type boundary is read through the same quoted-string rules (RFC 7578 §4.1)",
    arguments: [
        (#"multipart/form-data; boundary="a b""#, "a b"),
        ("multipart/form-data; boundary=xyz", "xyz"),
        ("multipart/form-data; charset=utf-8; boundary=xyz", "xyz"),
        (#"multipart/form-data; name="x; boundary=evil"; boundary=real"#, "real"),
        (#"multipart/form-data; boundary="a;b""#, nil),
        ("application/json", nil)
    ]
)
func boundaryUsesTheQuotedStringRules(_ contentType: String, _ expected: String?) {
    #expect(MultipartFormData.boundary(ofContentType: contentType) == expected)
}
