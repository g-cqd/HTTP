//
//  QPACKAllocationTests.swift
//  QPACKTests
//
//  Allocation ceilings for the QPACK hot path (RFC 9204 §4.5 decode, §4.3 encoder heuristic). The
//  200k-rps target needs the per-request field-section decode to stay allocation-light, so
//  `expectAllocations` (the libmalloc hook) trips deterministically if a re-introduced copy / box /
//  un-reserved growth regresses the budget — a mutation-resistant guard that runs in the normal
//  `swift test` CI gate and is machine-independent (allocation counts are exact, unlike wall-clock).
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import QPACK

@Suite("QPACK allocation ceilings — the low-alloc guarantee the throughput target needs")
struct QPACKAllocationTests {
    /// A realistic browser request field section (static-table references + literals; v1 has no
    /// dynamic table) — the per-request input the server QPACK-decodes on every HTTP/3 request.
    private static let requestFields: [HeaderField] = [
        HeaderField(name: ":method", value: "GET"),
        HeaderField(name: ":scheme", value: "https"),
        HeaderField(name: ":authority", value: "www.example.com"),
        HeaderField(name: ":path", value: "/api/v1/items?page=2&sort=desc"),
        HeaderField(name: "user-agent", value: "bench/1.0"),
        HeaderField(name: "accept", value: "text/html,application/json"),
        HeaderField(name: "accept-encoding", value: "gzip, deflate, br")
    ]

    @Test("decoding a realistic request field section stays within its allocation budget")
    func decodeRequestStaysWithinAllocationBudget() {
        let block = QPACKEncoder().encode(Self.requestFields)
        let decoder = QPACKDecoder()
        // Warm up once so one-time lazy init (e.g. the Huffman DFA) is not charged to the measured run.
        _ = block.withUnsafeBytes { raw in try? decoder.decode(raw.bytes) }
        // Measured budget: 6 — the literal values (`:authority` / `:path` / `user-agent` / `accept`)
        // plus the result array; the four fully static-table entries cost zero. Pinned tight so any
        // re-introduced per-field copy on the decode path trips this guard.
        _ = expectAllocations(noMoreThan: 6) {
            block.withUnsafeBytes { raw in
                _ = try? decoder.decode(raw.bytes)
            }
        }
    }

    @Test("a sighting in the saturated insert-on-second-use window allocates nothing (§4.3)")
    func recentFieldSightingAllocatesNothing() {
        // The window saturates almost immediately on a real connection, because a unique per-response
        // value (date, etag, content-length) is sighted once, never recurs, and is pushed out by the
        // next one — so the saturated state IS the steady state, and it must cost no heap traffic.
        // The ring is fixed-length and the position map churns keys within a reserved capacity, so a
        // sighting neither grows nor reallocates either one.
        var window = QPACKRecentFieldWindow(limit: 64)
        for index in 0 ..< 200 {
            _ = window.recordSighting(of: HeaderField(name: "etag", value: "\"tag-\(index)\""))
        }
        let novel = HeaderField(name: "etag", value: "\"tag-novel\"")
        expectAllocations(noMoreThan: 0) {
            _ = window.recordSighting(of: novel)
        }
    }
}
