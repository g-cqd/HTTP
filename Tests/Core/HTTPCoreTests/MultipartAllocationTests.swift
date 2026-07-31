//
//  MultipartAllocationTests.swift
//  HTTPCoreTests
//
//  RFC 7578 — the copy budget of a multipart parse, guarded rather than described. The parser borrows
//  the body as a `RawSpan` and addresses it by offset, so the only heap traffic a parse may produce is
//  what the returned value actually keeps: one array per part payload, and a `String` per header-derived
//  field too long for Swift's inline small-string form. Anything else — a whole-body copy to make the
//  opening delimiter uniform, a sub-array per part, a copy of each header section, a `[String: String]`
//  of every header line — is work done in order to throw it away, and each of those regressions moves
//  this count. The bound is per part and constant in body SIZE, which is the property that matters: a
//  parse whose allocation count tracks the payload length is copying the payload more than once.
//

import HTTPTestSupport
import Testing

@testable import HTTPCore

/// A body of `count` parts, each with a full header set and a `size`-byte payload.
private func form(parts count: Int, size: Int, boundary: String = "B") -> [UInt8] {
    let head =
        "--\(boundary)\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
        + "Content-Type: text/plain\r\n\r\n"
    let part = head + String(repeating: "x", count: size) + "\r\n"
    return Array((String(repeating: part, count: count) + "--\(boundary)--\r\n").utf8)
}

@Test("a parse allocates only what the parts retain — nothing per header line, nothing per body")
func parseAllocatesOnlyWhatPartsRetain() {
    let body = form(parts: 8, size: 64)
    _ = MultipartFormData.parse(body, boundary: "B")  // warm the one-time lazy initialization
    expectAllocations(noMoreThan: 24) {
        _ = MultipartFormData.parse(body, boundary: "B")
    }
}

@Test("allocation count is independent of body size — only the payload scales with the payload")
func allocationCountIsIndependentOfBodySize() {
    let small = form(parts: 4, size: 32)
    let large = form(parts: 4, size: 32_768)
    _ = MultipartFormData.parse(small, boundary: "B")
    _ = MultipartFormData.parse(large, boundary: "B")
    let smallCount = mallocDelta { _ = MultipartFormData.parse(small, boundary: "B") }
    let largeCount = mallocDelta { _ = MultipartFormData.parse(large, boundary: "B") }
    guard let smallCount, let largeCount else {
        return  // allocation counting is unavailable on this platform
    }
    #expect(largeCount == smallCount)
}

@Test("allocation count is independent of BOUNDARY length — the KMP table is not built per octet")
func allocationCountIsIndependentOfBoundaryLength() {
    // The suite's other cases all use the 1-octet boundary "B", which hid a cost that scales with the
    // delimiter rather than the body: `MultipartBoundary.failureTable` built its KMP table with a
    // `for index in 1 ..< n`, one heap allocation per iteration in the unoptimized test build. A real
    // browser boundary is ~37 octets (`----WebKitFormBoundary…`), so the parse a server actually runs
    // cost 55 allocations where this suite measured 19 — and the gap grew with any boundary a peer
    // chose. Both spellings are free in release; this guards the oracle above, not production.
    // Bound to `let`s: building these `String`s inside a measured closure would charge the
    // measurement for the literal itself, which is what it is trying to hold constant.
    let shortBoundary = "B"
    let browserBoundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    let maximalBoundary = String(repeating: "z", count: 70)
    let short = form(parts: 8, size: 64, boundary: shortBoundary)
    let browser = form(parts: 8, size: 64, boundary: browserBoundary)
    let maximal = form(parts: 8, size: 64, boundary: maximalBoundary)
    _ = MultipartFormData.parse(short, boundary: shortBoundary)
    _ = MultipartFormData.parse(browser, boundary: browserBoundary)
    _ = MultipartFormData.parse(maximal, boundary: maximalBoundary)
    let shortCount = mallocDelta { _ = MultipartFormData.parse(short, boundary: shortBoundary) }
    let browserCount = mallocDelta {
        _ = MultipartFormData.parse(browser, boundary: browserBoundary)
    }
    let maximalCount = mallocDelta {
        _ = MultipartFormData.parse(maximal, boundary: maximalBoundary)
    }
    guard let shortCount, let browserCount, let maximalCount else {
        return  // allocation counting is unavailable on this platform
    }
    #expect(browserCount == shortCount)
    #expect(maximalCount == shortCount)
}

@Test("a rejected body allocates nothing per part: the limit is checked before the copy")
func rejectedBodyDoesNotAllocatePerPart() {
    let body = form(parts: 64, size: 4_096)
    let limits = MultipartLimits(maxRetainedBytes: 1)
    _ = MultipartFormData.parse(body, boundary: "B", limits: limits)
    expectAllocations(noMoreThan: 10) {
        _ = MultipartFormData.parse(body, boundary: "B", limits: limits)
    }
}

@Test("a body of unparsable garbage allocates only the boundary's own two arrays")
func garbageBodyAllocatesOnlyTheBoundary() {
    let body = [UInt8](repeating: 0x41, count: 64_000)
    _ = MultipartFormData.parse(body, boundary: "B")
    expectAllocations(noMoreThan: 10) {
        _ = MultipartFormData.parse(body, boundary: "B")
    }
}
