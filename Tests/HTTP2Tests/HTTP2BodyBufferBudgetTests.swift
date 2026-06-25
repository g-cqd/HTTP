//
//  HTTP2BodyBufferBudgetTests.swift
//  HTTP2Tests
//
//  The HTTP/2 receive window replenishes *while a body is still buffering* (RFC 9113 §6.9), so the
//  per-stream `maxBodySize` cap alone lets a peer that opens many concurrent streams accumulate
//  maxConcurrentStreams × maxBodySize of un-dispatched request body — a memory-exhaustion vector.
//  These tests lock the connection-wide buffered-body budget that bounds the *sum* across streams,
//  and prove a dispatched (delivered) body is released from that budget so legitimate pipelining is
//  unaffected. Boundary-exact (mutation-resistant; see Tests/MUTATION-OPERATORS.md M1/M4).
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP2

@Suite("RFC 9113 §6.9 — connection request-body buffer budget", .tags(.mutation))
struct HTTP2BodyBufferBudgetTests {
    /// Two streams that each pass the per-stream cap can still exceed the connection-wide budget — the
    /// stream that crosses it is reset, not the one already buffered.
    @Test("the buffered body is bounded across streams, not just per-stream")
    func boundsConcurrentStreams() throws {
        var connection = try H2Wire.handshaked(limits: HTTPLimits(maxBodySize: 100))
        let sixty = [UInt8](repeating: 0x61, count: 60)
        // Stream 1 buffers 60 (≤ 100 per-stream and ≤ 100 connection) — accepted, left open.
        H2Wire.expectAccepted(
            H2Wire.openStream(streamID: 1)
                + H2Wire.data(streamID: 1, payload: sixty, endStream: false),
            on: &connection
        )
        // Stream 3's 60 would push the connection buffer to 120 > 100 — reset, though 60 ≤ the per-stream
        // cap on its own. The bound is the cross-stream sum.
        H2Wire.expectStreamError(
            .enhanceYourCalm,
            on: 3,
            feeding: H2Wire.openStream(streamID: 3)
                + H2Wire.data(streamID: 3, payload: sixty, endStream: false),
            connection: &connection
        )
    }

    /// The budget is inclusive — exactly the limit is allowed, one octet past it is reset.
    ///
    /// Pins the relational boundary against a `< ↔ <=` mutation (Tests/MUTATION-OPERATORS.md M1).
    @Test("exactly the budget across streams is allowed; one octet past it is reset")
    func boundaryIsInclusive() throws {
        var connection = try H2Wire.handshaked(limits: HTTPLimits(maxBodySize: 100))
        let fifty = [UInt8](repeating: 0x61, count: 50)
        H2Wire.expectAccepted(
            H2Wire.openStream(streamID: 1)
                + H2Wire.data(streamID: 1, payload: fifty, endStream: false),
            on: &connection
        )
        // 50 + 50 == 100 == the budget: still accepted (inclusive bound).
        H2Wire.expectAccepted(
            H2Wire.openStream(streamID: 3)
                + H2Wire.data(streamID: 3, payload: fifty, endStream: false),
            on: &connection
        )
        // One octet on a third stream is 101 > 100 — reset.
        H2Wire.expectStreamError(
            .enhanceYourCalm,
            on: 5,
            feeding: H2Wire.openStream(streamID: 5)
                + H2Wire.data(streamID: 5, payload: [0x61], endStream: false),
            connection: &connection
        )
    }

    /// A delivered (END_STREAM) body is released from the budget.
    ///
    /// Two sequential streams each carrying exactly the limit both succeed — a naive cumulative counter
    /// (or a budget that retained dispatched bodies) would wrongly reject the second.
    @Test("a dispatched body is released — sequential full-limit uploads both deliver")
    func dispatchedBodyIsReleased() throws {
        var connection = try H2Wire.handshaked(limits: HTTPLimits(maxBodySize: 100))
        let hundred = [UInt8](repeating: 0x61, count: 100)
        H2Wire.expectRequest(
            H2Wire.openStream(streamID: 1)
                + H2Wire.data(streamID: 1, payload: hundred, endStream: true),
            on: &connection
        )
        // Stream 1's body was delivered and released; stream 3 sees a clear budget and also delivers.
        H2Wire.expectRequest(
            H2Wire.openStream(streamID: 3)
                + H2Wire.data(streamID: 3, payload: hundred, endStream: true),
            on: &connection
        )
    }
}
