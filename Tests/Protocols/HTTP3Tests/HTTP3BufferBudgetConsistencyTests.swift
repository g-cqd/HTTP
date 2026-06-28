//
//  HTTP3BufferBudgetConsistencyTests.swift
//  HTTP3Tests
//
//  The connection-wide budgets — buffered request body (RFC 9114 §4.1) and blocked QPACK sections
//  (RFC 9204 §2.1.2) — are enforced in O(1) against `HTTP3StreamTable`'s `totalBufferedBody` and
//  `blockedSectionCount`, counters maintained on every table mutation rather than re-summed per frame.
//  Drift between a counter and the streams' actual state would silently weaken (or wrongly trip) a DoS
//  budget, so these tests pin the invariants `totalBufferedBody == Σ body.count` and
//  `blockedSectionCount == Σ (blockedSection != nil)` across buffer / dispatch (FIN) / block / reset.
//

import HTTPCore
import HTTPTestSupport
import QPACK
import Testing

@testable import HTTP3

@Suite(
    "RFC 9114 §4.1 / RFC 9204 §2.1.2 — buffered-body & blocked-section counter consistency",
    .tags(.mutation))
struct HTTP3BufferBudgetConsistencyTests: HTTP3WireFixtures {
    private static let streamA = QUICStreamID(0)
    private static let streamB = QUICStreamID(4)

    /// `totalBufferedBody` equals the recomputed cross-stream sum after each buffer, dispatch, and
    /// reset, and tracks the expected absolute totals as bytes are admitted and released.
    @Test("totalBufferedBody equals the live cross-stream body sum through buffer/dispatch/reset")
    func bodyCounterTracksBufferedBytes() throws {
        var connection = HTTP3Connection(limits: HTTPLimits(maxBodySize: 10_000))
        _ = connection.outbound()
        let post = requestFieldSection(method: "POST")
        expectConsistent(connection)

        // Two streams buffer bodies without FIN — both held un-dispatched.
        _ = try connection.receive(Self.streamA, requestStream(post, body: body(60)), fin: false)
        #expect(connection.streams.totalBufferedBody == 60)
        expectConsistent(connection)

        _ = try connection.receive(Self.streamB, requestStream(post, body: body(40)), fin: false)
        #expect(connection.streams.totalBufferedBody == 100)
        expectConsistent(connection)

        // FIN on stream A dispatches its request; the delivered body is released from the budget.
        _ = try connection.receive(Self.streamA, [], fin: true)
        #expect(connection.streams.totalBufferedBody == 40)
        expectConsistent(connection)

        // Resetting stream B evicts it entirely — the counter returns to zero.
        _ = connection.resetStream(Self.streamB, errorCode: 0)
        #expect(connection.streams.totalBufferedBody == 0)
        expectConsistent(connection)
    }

    /// `blockedSectionCount` tracks streams parked on not-yet-received QPACK inserts as they block and
    /// are evicted, while buffered-body stays zero (a blocked HEADERS section buffers no body).
    @Test("blockedSectionCount equals the live count of QPACK-blocked streams")
    func blockedCounterTracksBlockedStreams() throws {
        var connection = HTTP3Connection()
        _ = connection.outbound()
        expectConsistent(connection)

        // A field section whose Required Insert Count (4, per the §4.5.1 prefix) exceeds the decoder's
        // insert count (0) blocks the stream until the encoder delivers those inserts (RFC 9204 §2.1.2).
        _ = try connection.receive(Self.streamA, requestStream([0x05, 0x00]), fin: false)
        #expect(connection.streams.blockedSectionCount == 1)
        #expect(connection.streams.totalBufferedBody == 0)
        expectConsistent(connection)

        _ = try connection.receive(Self.streamB, requestStream([0x05, 0x00]), fin: false)
        #expect(connection.streams.blockedSectionCount == 2)
        expectConsistent(connection)

        // Resetting a blocked stream evicts it and clears its blocked-section contribution.
        _ = connection.resetStream(Self.streamA, errorCode: 0)
        #expect(connection.streams.blockedSectionCount == 1)
        expectConsistent(connection)

        _ = connection.resetStream(Self.streamB, errorCode: 0)
        #expect(connection.streams.blockedSectionCount == 0)
        expectConsistent(connection)
    }

    /// Both counters must equal the totals recomputed directly from the table's records.
    private func expectConsistent(
        _ connection: HTTP3Connection,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let recomputedBody = connection.streams.reduce(0) { $0 + $1.value.body.count }
        let recomputedBlocked = connection.streams.reduce(0) {
            $0 + ($1.value.blockedSection == nil ? 0 : 1)
        }
        #expect(
            connection.streams.totalBufferedBody == recomputedBody,
            "buffered-body counter drifted from the recomputed sum",
            sourceLocation: sourceLocation
        )
        #expect(
            connection.streams.blockedSectionCount == recomputedBlocked,
            "blocked-section counter drifted from the recomputed count",
            sourceLocation: sourceLocation
        )
    }

    private func body(_ count: Int) -> [UInt8] { [UInt8](repeating: 0x61, count: count) }
}
