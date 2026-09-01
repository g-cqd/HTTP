//
//  MultipartMatcherTests.swift
//  HTTPCoreTests
//
//  The delimiter matcher's complexity, pinned rather than assumed (CWE-407, inefficient algorithmic
//  complexity).
//
//  A naive substring search restarts one byte after each failed candidate and re-compares what it
//  already read, which is normally `O(haystack × needle)`. For THIS needle it is not, and the
//  distinction is worth stating because it is load-bearing. The needle is `CRLF "--" boundary` and
//  RFC 2046 §5.1.1 `bchars` excludes CR, so CR occurs in the needle only at offset 0. Any partial match
//  of two or more bytes therefore contains exactly one CR — its first — which makes such matches
//  pairwise disjoint: their lengths sum to at most the body length, and the naive scan is already
//  bounded at about `3 × body`. Measured on the worst partial-prefix flood that can be built against a
//  64-byte boundary, naive costs 539,933 comparisons where KMP costs 276,000 — a factor of 1.96, not
//  the factor of 70 an unconstrained needle would give.
//
//  Knuth-Morris-Pratt is adopted anyway because it makes that bound UNCONDITIONAL. The naive bound is a
//  consequence of the character-set validation, i.e. of a policy decision that a future maintainer could
//  reasonably relax to accept the boundaries some clients actually emit; KMP's `2 × body` follows from
//  the algorithm and survives that. It also halves the comparisons on the adversarial input and reads
//  each byte exactly once, which matters more than the comparison count on a body large enough to miss
//  cache. The assertions below are on the comparison count rather than on elapsed time: a property of
//  the algorithm is deterministic, where a wall-clock ratio would flake under CI load.
//

import Testing

@testable import HTTPCore

/// The outcome of one instrumented parse: the form, and the matcher's byte-comparison count.
private typealias Measured = (form: MultipartFormData?, compares: Int)

/// Parses `body` with the internal parser and reports the matcher's byte-comparison count.
private func measure(_ body: [UInt8], boundary: String) -> Measured {
    guard let validated = MultipartBoundary(boundary) else {
        return (nil, 0)
    }
    return body.withUnsafeBytes { raw in
        var parser = MultipartParser(
            body: raw.bytes,
            boundary: validated,
            limits: MultipartLimits()
        )
        let form = parser.parse()
        return (form, parser.byteComparisons)
    }
}

/// A one-part body whose payload is `payload`, framed by `boundary`.
private func framed(_ boundary: String, payload: String) -> [UInt8] {
    let head = "--\(boundary)\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n"
    return Array((head + payload + "\r\n--\(boundary)--\r\n").utf8)
}

@Test("a partial-prefix flood stays linear: comparisons never exceed twice the body length")
func partialPrefixFloodStaysLinear() {
    // Every 68-byte run matches 67 bytes of the 68-byte delimiter and then fails on the last one —
    // the worst case for a search that restarts one byte later and re-reads what it already matched.
    let boundary = String(repeating: "a", count: 64)
    let nearMiss = "\r\n--" + String(repeating: "a", count: 63) + "X"
    let body = framed(boundary, payload: String(repeating: nearMiss, count: 4_000))
    let (form, compares) = measure(body, boundary: boundary)
    #expect(form?.parts.count == 1)
    #expect(compares <= 2 * body.count)
}

@Test("a flood of full-length near misses that differ only in the final byte is linear too")
func trailingByteNearMissesStayLinear() {
    let boundary = String(repeating: "z", count: 70)
    let nearMiss = "\r\n--" + String(repeating: "z", count: 69) + "y"
    let body = framed(boundary, payload: String(repeating: nearMiss, count: 4_000))
    let (form, compares) = measure(body, boundary: boundary)
    #expect(form?.parts.count == 1)
    #expect(compares <= 2 * body.count)
}

@Test("a flood of valid delimiters followed by junk suffixes is linear as well")
func rejectedDelimiterSuffixesStayLinear() {
    // The boundary matches every time; only the RFC 2046 §5.1.1 suffix check rejects it. The scan must
    // resume from the automaton state it already reached, not rewind to the candidate's start.
    let boundary = String(repeating: "b", count: 64)
    let junk = "\r\n--" + boundary + "JUNK"
    let body = framed(boundary, payload: String(repeating: junk, count: 4_000))
    let (form, compares) = measure(body, boundary: boundary)
    #expect(form?.parts.count == 1)
    #expect(compares <= 2 * body.count)
}

@Test("an ordinary body costs about one comparison per byte, not two")
func ordinaryBodyCostsOneComparisonPerByte() {
    let payload = String(repeating: "payload bytes, no prefixes. ", count: 500)
    let body = framed("BOUNDARY", payload: payload)
    let (form, compares) = measure(body, boundary: "BOUNDARY")
    #expect(form?.parts.count == 1)
    #expect(compares <= body.count + 8)
}

@Test("the failure table has no proper border, because bchars excludes CR (RFC 2046 §5.1.1)")
func delimiterNeedleCannotSelfOverlap() {
    let boundary = MultipartBoundary("aa-aa")
    #expect(boundary?.failure.allSatisfy { $0 == 0 } == true)
    #expect(boundary?.failure.count == (boundary?.delimiter.count).map { $0 + 1 })
}

@Test("the failure table is still a correct KMP table for a needle that does self-overlap")
func failureTableIsCorrectForABorderedNeedle() {
    // Not reachable through a valid boundary, but the matcher must not depend on that to be linear.
    #expect(MultipartBoundary.failureTable(Array("ababa".utf8)) == [0, 0, 0, 1, 2, 3])
    #expect(MultipartBoundary.failureTable(Array("aaaa".utf8)) == [0, 0, 1, 2, 3])
    #expect(MultipartBoundary.failureTable(Array("abcd".utf8)) == [0, 0, 0, 0, 0])
}
