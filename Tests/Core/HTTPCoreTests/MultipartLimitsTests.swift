//
//  MultipartLimitsTests.swift
//  HTTPCoreTests
//
//  RFC 7578 — the multipart caps that the request-body limit cannot express. `maxBodySize` bounds the
//  *wire* bytes; it says nothing about how much structure those bytes can force the parser to build.
//  One megabyte of empty parts is tens of thousands of owned `Part` values; one megabyte spent entirely
//  on a single part's header section is a header allocation of that size; and the parsed form retains a
//  second copy of nearly every payload byte. Each is CWE-770 (allocation without limits) reached through
//  a request that never exceeds the body cap.
//

import Testing

@testable import HTTPCore

/// A body of `count` parts, each named `f<index>` and carrying `payload`.
private func parts(_ count: Int, payload: String = "v", named: Bool = true) -> [UInt8] {
    var lines: [String] = []
    for index in 0 ..< count {
        lines.append("--B")
        if named {
            lines.append(#"Content-Disposition: form-data; name="f\#(index)""#)
        }
        else {
            lines.append("Content-Type: text/plain")
        }
        lines.append("")
        lines.append(payload)
    }
    lines.append("--B--")
    lines.append("")
    return Array(lines.joined(separator: "\r\n").utf8)
}

@Test("the part count is capped independently of the body size")
func partCountIsCapped() {
    let limits = MultipartLimits(maxParts: 3)
    #expect(MultipartFormData.parse(parts(3), boundary: "B", limits: limits)?.parts.count == 3)
    #expect(MultipartFormData.parse(parts(4), boundary: "B", limits: limits) == nil)
}

@Test("parts skipped for having no Content-Disposition name still count toward the cap")
func skippedPartsStillCountTowardTheCap() {
    let limits = MultipartLimits(maxParts: 3)
    let flood = parts(50, named: false)
    #expect(MultipartFormData.parse(flood, boundary: "B", limits: limits) == nil)
    #expect(MultipartFormData.parse(flood, boundary: "B")?.parts.isEmpty == true)
}

@Test("a part header section larger than the per-part cap rejects the body")
func partHeaderBytesAreCapped() {
    let padding = String(repeating: "x", count: 200)
    let body = Array(
        [
            "--B",
            #"Content-Disposition: form-data; name="f""#,
            "X-Padding: " + padding,
            "",
            "v",
            "--B--",
            ""
        ]
        .joined(separator: "\r\n").utf8
    )
    #expect(MultipartFormData.parse(body, boundary: "B", limits: MultipartLimits()) != nil)
    let tight = MultipartLimits(maxPartHeaderBytes: 64)
    #expect(MultipartFormData.parse(body, boundary: "B", limits: tight) == nil)
}

@Test("the aggregate retained byte count is capped across all parts, not per part")
func retainedBytesAreCappedInAggregate() {
    let body = parts(4, payload: String(repeating: "p", count: 100))
    #expect(MultipartFormData.parse(body, boundary: "B", limits: MultipartLimits()) != nil)
    let tight = MultipartLimits(maxRetainedBytes: 250)
    #expect(MultipartFormData.parse(body, boundary: "B", limits: tight) == nil)
}

@Test("the retained cap counts the header-derived names too, not only payload bytes")
func retainedBytesIncludeNames() {
    let body = parts(1, payload: "")
    let tight = MultipartLimits(maxRetainedBytes: 1)
    #expect(MultipartFormData.parse(body, boundary: "B", limits: MultipartLimits()) != nil)
    #expect(MultipartFormData.parse(body, boundary: "B", limits: tight) == nil)
}

@Test(
    "a non-positive cap admits nothing rather than being silently treated as unlimited",
    arguments: [
        MultipartLimits(maxParts: 0),
        MultipartLimits(maxPartHeaderBytes: -1),
        MultipartLimits(maxRetainedBytes: 0)
    ]
)
func nonPositiveCapsAdmitNothing(_ limits: MultipartLimits) {
    #expect(MultipartFormData.parse(parts(1), boundary: "B", limits: limits) == nil)
}

@Test("the default limits accept an ordinary browser form untouched")
func defaultLimitsAcceptAnOrdinaryForm() {
    let form = MultipartFormData.parse(parts(12), boundary: "B")
    #expect(form?.parts.count == 12)
    #expect(form?["f0"]?.body == Array("v".utf8))
}

@Test("the decoder carries its own limits through to the parser")
func decoderCarriesItsLimits() throws {
    let contentType = "multipart/form-data; boundary=B"
    let decoder = MultipartFormDecoder(limits: MultipartLimits(maxParts: 1))
    #expect(throws: BodyDecodingError.malformed) {
        try decoder.decode(parts(2), contentType: contentType)
    }
    let permissive = try MultipartFormDecoder().decode(parts(2), contentType: contentType)
    #expect(permissive.parts.count == 2)
}
