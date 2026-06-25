//
//  HTTP2PriorityTests.swift
//  HTTP2Tests
//
//  RFC 9218 Extensible Prioritization — the HTTP/2 send-side scheduler. When the *shared* connection
//  send window (RFC 9113 §6.9.1) is the bottleneck, `flushAll` must release a more-urgent stream's
//  DATA before a less-urgent one competing for the same window (RFC 9218 §4). These tests exhaust the
//  connection window, queue two prioritized responses (always opened in the ascending stream-id order
//  §5.1.1 requires), then re-open a one-stream sliver and assert which stream wins it — distinguishing
//  priority ordering from incidental dictionary-iteration order.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9218 — HTTP/2 priority scheduling")
struct HTTP2PriorityTests {
    /// A complete GET carrying `Priority: u=<urgency>` (RFC 9218 §4.1).
    private func prioritizedGet(streamID: UInt32, urgency: Int) -> [UInt8] {
        H2Wire.headers(
            streamID: streamID,
            fields: H2Wire.requestFields(
                extra: [HPACKField(name: "priority", value: "u=\(urgency)")]
            ),
            endStream: true
        )
    }

    /// Drives a handshaked connection to a state where the connection send window is exhausted and two
    /// streams have fully-deferred 100-octet responses queued: stream 3 (the *earlier*, body `"E"`) and
    /// stream 5 (the *later*, body `"L"`), opened in that ascending-id order with the given urgencies.
    ///
    /// The window is first drained by a throwaway stream that sends exactly the fixed 65,535-octet
    /// connection window (RFC 9113 §6.9.2), so afterwards only DATA explicitly released by a
    /// WINDOW_UPDATE appears — and the body byte (`E`/`L`) names which stream the scheduler chose.
    private func congested(earlierUrgency: Int, laterUrgency: Int) throws -> HTTP2Connection {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.get(streamID: 1))
        _ = connection.outboundBytes()
        try connection.respond(
            to: HTTP2StreamID(1),
            HTTPResponse(status: .ok),
            body: [UInt8](repeating: UInt8(ascii: "."), count: 65_535)
        )
        _ = connection.outboundBytes()  // drained; the connection send window is now 0

        _ = try connection.receive(prioritizedGet(streamID: 3, urgency: earlierUrgency))
        try connection.respond(
            to: HTTP2StreamID(3),
            HTTPResponse(status: .ok),
            body: [UInt8](repeating: UInt8(ascii: "E"), count: 100)
        )
        _ = try connection.receive(prioritizedGet(streamID: 5, urgency: laterUrgency))
        try connection.respond(
            to: HTTP2StreamID(5),
            HTTPResponse(status: .ok),
            body: [UInt8](repeating: UInt8(ascii: "L"), count: 100)
        )
        // Both responses' HEADERS flushed (not flow-controlled), but no DATA — the window is exhausted.
        #expect(H2Wire.dataPayload(in: connection.outboundBytes()).bytes.isEmpty)
        return connection
    }

    /// Re-opens exactly `5` octets of connection window and returns the single DATA payload released.
    private func flushOneSliver(_ connection: inout HTTP2Connection) throws -> [UInt8] {
        _ = try connection.receive(H2Wire.windowUpdate(streamID: 0, increment: 5))
        return H2Wire.dataPayload(in: connection.outboundBytes()).bytes
    }

    @Test("§4 — a later but more-urgent stream wins the window over an earlier less-urgent one")
    func laterHigherUrgencyWins() throws {
        // Stream 5 (later, u=0) must beat stream 3 (earlier, u=7): only urgency can invert arrival/id.
        var connection = try congested(earlierUrgency: 7, laterUrgency: 0)
        #expect(try flushOneSliver(&connection) == [UInt8](repeating: UInt8(ascii: "L"), count: 5))
    }

    @Test("§4 — an earlier more-urgent stream keeps the window over a later less-urgent one")
    func earlierHigherUrgencyWins() throws {
        // Stream 3 (earlier, u=0) beats stream 5 (later, u=7): urgency never inverts in its favour.
        var connection = try congested(earlierUrgency: 0, laterUrgency: 7)
        #expect(try flushOneSliver(&connection) == [UInt8](repeating: UInt8(ascii: "E"), count: 5))
    }

    @Test("§4 — equal urgency falls back to the lower stream id, deterministically")
    func equalUrgencyBreaksTowardLowerStreamID() throws {
        // Same urgency on both: the tie-break is the lower id (stream 3), so the order is stable rather
        // than dependent on dictionary iteration.
        var connection = try congested(earlierUrgency: 3, laterUrgency: 3)
        #expect(try flushOneSliver(&connection) == [UInt8](repeating: UInt8(ascii: "E"), count: 5))
    }
}
