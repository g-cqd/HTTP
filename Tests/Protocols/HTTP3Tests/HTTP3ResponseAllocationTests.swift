//
//  HTTP3ResponseAllocationTests.swift
//  HTTP3Tests
//
//  Allocation ceiling for the HTTP/3 response-encode hot path (RFC 9114 §4.1). Every response
//  QPACK-encodes its field section; the 200k-rps target needs that to stay allocation-light, so
//  `expectAllocations` (the libmalloc hook) trips deterministically if a re-introduced array rebuild,
//  un-reserved buffer growth, or per-status itoa regresses the budget — a machine-independent guard.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP3

@Suite("HTTP/3 response-encode allocation ceiling (RFC 9114 §4.1)")
struct HTTP3ResponseAllocationTests {
    /// A realistic small response: `:status` plus the fields the example's middleware stamps.
    private static func response() -> HTTPResponse {
        var fields = HTTPFields()
        _ = fields.setValue("text/plain; charset=utf-8", for: .contentType)
        _ = fields.setValue("httpd-example", for: .server)
        _ = fields.setValue("Wed, 25 Jun 2026 12:00:00 GMT", for: .date)
        _ = fields.setValue("nosniff", for: .xContentTypeOptions)
        _ = fields.setValue("max-age=3600", for: .cacheControl)
        return HTTPResponse(status: .ok, headerFields: fields)
    }

    @Test("encoding a realistic response field section stays within its allocation budget")
    func encodeResponseStaysWithinBudget() {
        let connection = HTTP3Connection()
        let response = Self.response()
        // Warm up once so one-time lazy init (the Huffman DFA, the status-string cache) is not charged
        // to the measured run.
        _ = connection.encodeResponseSection(response)
        // Measured budget: 1 — the reserved output buffer, and nothing else. The QPACK encode appends
        // straight into it, the `:status` string is cached, and the intermediate [HeaderField] array
        // is gone.
        //
        // The ceiling was 11, described as "one reserved output buffer plus the per-field cost of
        // iterating HTTPFields". That reading was right, and the per-field cost turned out to be the
        // whole of it: `for field in response.headerFields` costs ~2 allocations per field in the
        // unoptimized test build, so the five-field response paid 10 of the 11 for its own iterator.
        // With the loop indexed the described floor — the one reserved buffer — is all that remains.
        _ = expectAllocations(noMoreThan: 3) {
            _ = connection.encodeResponseSection(response)
        }
    }

    @Test("the encode cost does not scale with the field count")
    func encodeCostDoesNotScaleWithFieldCount() {
        var wide = HTTPFields()
        var index = 0
        while index < 24 {
            _ = wide.append("v\(index)", for: .server)
            index += 1
        }
        let connection = HTTP3Connection()
        let narrow = Self.response()
        let response = HTTPResponse(status: .ok, headerFields: wide)
        _ = connection.encodeResponseSection(narrow)
        _ = connection.encodeResponseSection(response)
        let narrowCost = mallocDelta { _ = connection.encodeResponseSection(narrow) }
        let wideCost = mallocDelta { _ = connection.encodeResponseSection(response) }
        guard let narrowCost, let wideCost else {
            return  // allocation counting is unavailable on this platform
        }
        // The property rather than a number: 24 fields encode into the same one reserved buffer as 5.
        // A re-introduced `for-in` breaks this first, and a single-field-count ceiling cannot see a
        // slope at all.
        #expect(wideCost == narrowCost)
    }
}
