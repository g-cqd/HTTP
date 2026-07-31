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
        // Measured floor: 3 — the owned HTTPRequest's `HTTPFields` storage growth. The four
        // pseudo-header values and the request struct cost nothing extra: the values are retained
        // references to the decoder's existing `String`s, not fresh copies.
        //
        // This floor was pinned at 17 until the mapper's `for field in fields` became an indexed
        // `while`. Fourteen of that 17 was `IndexingIterator.next()` traffic in the unoptimized test
        // build — the oracle was mostly measuring itself, and a regression that doubled the real cost
        // would have sailed under the ceiling. The tight 5 is what makes this a guard rather than a
        // description; it leaves headroom for a toolchain difference and nothing else.
        _ = expectAllocations(noMoreThan: 5) {
            _ = try? RequestMapper.makeRequest(from: Self.fields) { _ in CancellationError() }
        }
    }

    @Test("the mapping cost does not scale with the field count — no per-field iterator traffic")
    func mapCostDoesNotScaleWithFieldCount() {
        let many = Self.fields + (0 ..< 40).map { HeaderField(name: "x-pad-\($0)", value: "v") }
        _ = try? RequestMapper.makeRequest(from: Self.fields) { _ in CancellationError() }
        _ = try? RequestMapper.makeRequest(from: many) { _ in CancellationError() }
        let few = mallocDelta {
            _ = try? RequestMapper.makeRequest(from: Self.fields) { _ in CancellationError() }
        }
        let lots = mallocDelta {
            _ = try? RequestMapper.makeRequest(from: many) { _ in CancellationError() }
        }
        guard let few, let lots else {
            return  // allocation counting is unavailable on this platform
        }
        // 47 fields against 7 may cost a few more `HTTPFields` storage re-grows, but nothing
        // proportional: a per-field allocation would put this ratio near 6.7x, not under 3x.
        #expect(lots < few * 3)
    }
}
