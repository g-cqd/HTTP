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
        // Measured budget: 11 — one reserved output buffer plus the per-field cost of iterating
        // HTTPFields; the QPACK encode appends straight into the reserved buffer, the :status string is
        // cached, and the intermediate [HeaderField] array is gone. This was **31** before the borrowing
        // refactor; the ceiling trips if the array rebuild, un-reserved growth, or per-status itoa returns.
        _ = expectAllocations(noMoreThan: 11) {
            _ = connection.encodeResponseSection(response)
        }
    }
}
