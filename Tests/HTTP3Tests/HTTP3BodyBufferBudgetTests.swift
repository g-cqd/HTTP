//
//  HTTP3BodyBufferBudgetTests.swift
//  HTTP3Tests
//
//  Parity with the HTTP/2 connection buffered-body budget (RFC 9114 §4.1): the per-stream `maxBodySize`
//  cap alone lets a peer that opens many concurrent request streams accumulate up to the concurrent-
//  stream count × maxBodySize of un-dispatched request body — a memory-exhaustion vector. These tests
//  lock the connection-wide bound on the *sum* across streams and the release of a body on dispatch
//  (FIN), so legitimate sequential uploads are unaffected. Boundary-exact (mutation-resistant; see
//  Tests/MUTATION-OPERATORS.md M1/M4).
//

import HTTPCore
import HTTPTestSupport
import QPACK
import Testing

@testable import HTTP3

@Suite("RFC 9114 §4.1 — connection request-body buffer budget", .tags(.mutation))
struct HTTP3BodyBufferBudgetTests: HTTP3WireFixtures {
    private static let streamA = QUICStreamID(0)  // client-initiated bidirectional request streams
    private static let streamB = QUICStreamID(4)
    private static let streamC = QUICStreamID(8)

    /// Two streams that each pass the per-stream cap can still exceed the connection-wide budget — the
    /// stream that crosses it is reset (H3_EXCESSIVE_LOAD), not the one already buffered.
    @Test("the buffered body is bounded across streams, not just per-stream")
    func boundsConcurrentStreams() throws {
        var connection = HTTP3Connection(limits: HTTPLimits(maxBodySize: 100))
        let post = requestFieldSection(method: "POST")
        let sixty = [UInt8](repeating: 0x61, count: 60)
        // Stream A buffers 60 (≤ 100 per-stream and ≤ 100 connection) — accepted, left open (no FIN).
        _ = try connection.receive(Self.streamA, requestStream(post, body: sixty), fin: false)
        #expect(resetStreamCode(&connection) == nil)
        // Stream B's 60 would push the connection buffer to 120 > 100 — reset, though 60 ≤ the per-stream
        // cap on its own.
        _ = try connection.receive(Self.streamB, requestStream(post, body: sixty), fin: false)
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
    }

    /// The budget is inclusive — exactly the limit is allowed, one octet past it is reset.
    ///
    /// Pins the relational boundary against a `< ↔ <=` mutation (Tests/MUTATION-OPERATORS.md M1).
    @Test("exactly the budget across streams is allowed; one octet past it is reset")
    func boundaryIsInclusive() throws {
        var connection = HTTP3Connection(limits: HTTPLimits(maxBodySize: 100))
        let post = requestFieldSection(method: "POST")
        let fifty = [UInt8](repeating: 0x61, count: 50)
        _ = try connection.receive(Self.streamA, requestStream(post, body: fifty), fin: false)
        #expect(resetStreamCode(&connection) == nil)
        // 50 + 50 == 100 == the budget: still accepted (inclusive bound).
        _ = try connection.receive(Self.streamB, requestStream(post, body: fifty), fin: false)
        #expect(resetStreamCode(&connection) == nil)
        // One octet on a third stream is 101 > 100 — reset.
        _ = try connection.receive(Self.streamC, requestStream(post, body: [0x61]), fin: false)
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
    }

    /// A delivered (FIN) body is released from the budget.
    ///
    /// Two sequential streams each carrying exactly the limit both deliver — a naive cumulative counter
    /// (or a budget that retained dispatched bodies) would wrongly reject the second.
    @Test("a dispatched body is released — sequential full-limit uploads both deliver")
    func dispatchedBodyIsReleased() throws {
        var connection = HTTP3Connection(limits: HTTPLimits(maxBodySize: 100))
        let post = requestFieldSection(
            method: "POST", extra: [HeaderField(name: "content-length", value: "100")]
        )
        let stream = requestStream(post, body: [UInt8](repeating: 0x61, count: 100))
        // Stream A carries exactly the limit, FINs, and delivers — releasing its body from the budget.
        guard case .request = try connection.receive(Self.streamA, stream, fin: true).first else {
            Issue.record("stream A should deliver its request")
            return
        }
        // Stream B then sees a clear budget and also delivers — a retained body would reject it.
        guard case .request = try connection.receive(Self.streamB, stream, fin: true).first else {
            Issue.record("stream B should deliver after stream A's body is released")
            return
        }
    }
}
