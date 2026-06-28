//
//  HTTP2BufferBudgetConsistencyTests.swift
//  HTTP2Tests
//
//  The connection-wide buffered-body budget (RFC 9113 §6.9) is enforced in O(1) against
//  `HTTP2StreamTable.totalBufferedBody`, a counter maintained on every table mutation rather than
//  re-summed per DATA frame. Drift between that counter and the streams' actual buffered bytes would
//  silently weaken (or wrongly trip) the DoS budget, so these tests pin the invariant
//  `totalBufferedBody == Σ body.count` across the operations that move bytes: buffering, dispatch on
//  END_STREAM (release), and reset (eviction). Boundary-exact (see Tests/MUTATION-OPERATORS.md M4).
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP2

@Suite("RFC 9113 §6.9 — buffered-body counter consistency", .tags(.mutation))
struct HTTP2BufferBudgetConsistencyTests {
    /// The running counter equals the recomputed cross-stream sum after each buffer, dispatch, and
    /// reset — and tracks the expected absolute totals as bytes are admitted and released.
    @Test("totalBufferedBody equals the live cross-stream body sum through buffer/dispatch/reset")
    func counterTracksBufferedBody() throws {
        var connection = try H2Wire.handshaked(limits: HTTPLimits(maxBodySize: 10_000))
        expectConsistent(connection)
        #expect(connection.streams.totalBufferedBody == 0)

        // Two streams buffer bodies without END_STREAM — both are held un-dispatched.
        _ = try connection.receive(
            H2Wire.openStream(streamID: 1)
                + H2Wire.data(streamID: 1, payload: body(60), endStream: false)
        )
        #expect(connection.streams.totalBufferedBody == 60)
        expectConsistent(connection)

        _ = try connection.receive(
            H2Wire.openStream(streamID: 3)
                + H2Wire.data(streamID: 3, payload: body(40), endStream: false)
        )
        #expect(connection.streams.totalBufferedBody == 100)
        expectConsistent(connection)

        // A third stream that buffers and ends in one batch dispatches immediately: its bytes are
        // admitted then released within the call, leaving the standing total unchanged.
        _ = try connection.receive(
            H2Wire.openStream(streamID: 5)
                + H2Wire.data(streamID: 5, payload: body(50), endStream: true)
        )
        #expect(connection.streams.totalBufferedBody == 100)
        expectConsistent(connection)

        // Ending stream 1 dispatches its request; the delivered body is released from the budget.
        _ = try connection.receive(H2Wire.data(streamID: 1, payload: [], endStream: true))
        #expect(connection.streams.totalBufferedBody == 40)
        expectConsistent(connection)

        // Resetting stream 3 evicts it entirely — the counter returns to zero.
        _ = try connection.receive(H2Wire.rstStream(streamID: 3))
        #expect(connection.streams.totalBufferedBody == 0)
        expectConsistent(connection)
    }

    /// `totalBufferedBody` must equal the sum recomputed directly from the table's records.
    private func expectConsistent(
        _ connection: HTTP2Connection,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let recomputed = connection.streams.reduce(0) { $0 + $1.value.body.count }
        #expect(
            connection.streams.totalBufferedBody == recomputed,
            "counter drifted from the recomputed cross-stream sum",
            sourceLocation: sourceLocation
        )
    }

    private func body(_ count: Int) -> [UInt8] { [UInt8](repeating: 0x61, count: count) }
}
