//
//  HTTP2ResponseAllocationTests.swift
//  HTTP2Tests
//
//  Allocation ceiling for the HTTP/2 response-encode hot path (RFC 9113 §8.3.2). Every response
//  HPACK-encodes its field section; the 200k-rps target needs that allocation-light, so
//  `expectAllocations` (the libmalloc hook) trips deterministically if a re-introduced array rebuild,
//  un-reserved buffer growth, per-status itoa, or per-field `rawName` materialization regresses it.
//  Measured on the warm (second) encode — the steady state of a long-lived connection whose HPACK
//  dynamic table has settled.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP2

@Suite("HTTP/2 response-encode allocation ceiling (RFC 9113 §8.3.2)")
struct HTTP2ResponseAllocationTests {
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
        var connection = HTTP2Connection()
        let response = Self.response()
        // Warm up so lazy init (the Huffman DFA) and the HPACK dynamic table reach steady state — not
        // charged to the measured run.
        _ = connection.encodeResponseSection(response)
        // Measured budget: 41 — down from 58 before the borrow refactor (the [HPACKField] array, the
        // per-field `rawName` materialization, the status itoa, and the un-reserved buffer growth are
        // gone). The residual is HPACK's stateful dynamic-table work + the HTTPFields iteration — a
        // deeper, separate opportunity (the audit's O(n) HPACK dynamic lookup). The ceiling trips if the
        // array rebuild / rawName / itoa returns.
        _ = expectAllocations(noMoreThan: 41) {
            _ = connection.encodeResponseSection(response)
        }
    }
}
