//
//  RequestMapperAllocationTests.swift
//  HTTPCoreTests
//
//  Allocation floor for the shared request mapping (RFC 9113 §8.3 / RFC 9114 §4.3) — the step both the
//  HTTP/2 and HTTP/3 receive paths run after header decode. The dispatched `HTTPRequest` *escapes* the
//  receive call (it is handed to the responder), so its pseudo-header values and `HTTPFields` must be
//  owned: this pins how much of that owned representation is irreducible, guarding the floor against a
//  regression (a re-introduced double-materialization) without claiming the unavoidable part is a bug.
//

import HTTPCore
import HTTPTestSupport
import Testing

@Suite("Request mapping — allocation floor for the owned HTTPRequest (RFC 9113 §8.3 / 9114 §4.3)")
struct RequestMapperAllocationTests {
    /// A realistic decoded GET field list (4 pseudo-headers + 3 regular fields).
    private static let fields: [HeaderField] = [
        HeaderField(name: ":method", value: "GET"),
        HeaderField(name: ":scheme", value: "https"),
        HeaderField(name: ":authority", value: "www.example.com"),
        HeaderField(name: ":path", value: "/api/v1/items?page=2&sort=desc"),
        HeaderField(name: "user-agent", value: "bench/1.0"),
        HeaderField(name: "accept", value: "text/html,application/json"),
        HeaderField(name: "accept-encoding", value: "gzip, deflate, br")
    ]

    @Test("mapping a decoded field list to an HTTPRequest stays within its allocation floor")
    func mapStaysWithinFloor() {
        // Warm up once so any one-time lazy init is not charged to the measured run.
        _ = try? RequestMapper.makeRequest(from: Self.fields) { _ in CancellationError() }
        // Measured floor: 17 — the owned HTTPRequest the responder receives (its HTTPFields storage, the
        // four pseudo-header values, and the request struct). It is *not* redundant lowercasing
        // (HTTPFieldName already reuses an already-lowercase name) and the QPACK decode is a separate 6
        // (QPACKAllocationTests). Most is irreducible without owning less of the escaping request; the
        // ceiling guards against a re-introduced double-materialization on the receive path.
        _ = expectAllocations(noMoreThan: 17) {
            _ = try? RequestMapper.makeRequest(from: Self.fields) { _ in CancellationError() }
        }
    }
}
