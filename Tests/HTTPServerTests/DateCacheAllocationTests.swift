//
//  DateCacheAllocationTests.swift
//  HTTPServerTests
//
//  The `Date` header (RFC 9110 §6.6.1) must be formatted once per second, not per response — at the
//  200k-rps target a per-response IMF-fixdate build is pure waste. These guard the per-second cache:
//  a warm same-second lookup is allocation-free (the shared string is reused), and the value advances
//  when the whole-second tick does.
//

import HTTPTestSupport
import Testing

@testable import HTTPServer

@Suite("DateCache — the Date header is formatted once per second, not per response")
struct DateCacheAllocationTests {
    @Test("a warm same-second lookup reuses the cached string with zero allocations")
    func warmLookupIsAllocationFree() {
        let cache = DateCache()
        let second = 1_782_000_000
        _ = cache.formatted(for: second)  // cold: builds + caches the IMF-fixdate string
        _ = expectAllocations(noMoreThan: 0) {
            _ = cache.formatted(for: second)  // warm: the same second reuses the string, no rebuild
        }
    }

    @Test("the cached value advances when the whole-second tick changes")
    func valueAdvancesAcrossSeconds() {
        let cache = DateCache()
        let base = 1_782_000_000
        let first = cache.formatted(for: base)
        let again = cache.formatted(for: base)
        #expect(first == again, "the same second must reuse the cached string")
        #expect(
            first != cache.formatted(for: base + 86_400),
            "a different day must produce a different IMF-fixdate string"
        )
    }
}
