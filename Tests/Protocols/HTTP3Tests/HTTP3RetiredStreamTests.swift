//
//  HTTP3RetiredStreamTests.swift
//  HTTP3Tests
//
//  R5-P0c, second property — retirement is terminal.
//
//  The engine is sans-I/O and creates a stream record lazily, from the id class of whatever octets it is
//  handed. That made retirement a suggestion rather than a fact: a driver that reset a stream and
//  retired its record still had octets queued for it — in the transport, in a reader task's in-flight
//  chunk, in a mailbox — and the next `receive` simply built the record again. The stream came back,
//  with a fresh parser buffer, a fresh slot in the buffered-body budget (RFC 9114 §4.1) and a fresh
//  chance at the SETTINGS_QPACK_BLOCKED_STREAMS allowance (RFC 9204 §2.1.2), and the abuse charge the
//  reset cost the peer bought it nothing.
//
//  The bound must not be a growing set of retired ids: a long-lived connection serves an unbounded
//  number of streams, so remembering each one is the same leak in a different table (CWE-770). Nor can
//  it be a bare "highest retired id" watermark, which is the obvious O(1) answer and is wrong — streams
//  do not retire in id order, so answering stream 4 while stream 0 has QUIC-opened but not yet sent its
//  HEADERS would cover 0 and silently drop a live request. What holds is a run of retired ids that
//  starts at 0 and grows one stride at a time, with the out-of-order remainder held apart until the run
//  reaches it (see ``HTTP3RetiredStreams``).
//
//  Standards: RFC 9114 §4.1, §8.1; RFC 9204 §2.1.2; RFC 9000 §2.1, §3.2.
//

import HTTPCore
import QPACK
import Testing

@testable import HTTP3

@Suite("HTTP/3 engine — a retired stream stays retired (R5-P0c)")
struct HTTP3RetiredStreamTests {
    /// The ways a request stream's record leaves the engine, all of which must be terminal.
    enum Retirement: String, CaseIterable, Sendable {
        /// The driver abandoned the stream — a lapsed deadline, an EOF, a refused tunnel (§8.1).
        case driverReset
        /// The response was encoded and the stream FINned (RFC 9114 §4.1).
        case answered
    }

    @Test(
        "queued octets arriving after retirement never rebuild the record",
        arguments: Retirement.allCases
    )
    func lateOctetsCannotResurrectAStream(_ retirement: Retirement) throws {
        var connection = HTTP3Connection()
        let stream = QUICStreamID(0)

        // A complete HEADERS plus a DATA prefix: real retained state, not an empty record.
        _ = try connection.receive(stream, Self.partialRequest(), fin: false)
        #expect(connection.census.trackedStreams == 1)
        #expect(connection.census.bufferedRequestBodyBytes > 0)

        switch retirement {
            case .driverReset:
                _ = connection.resetStream(stream, errorCode: 0x010C)
            case .answered:
                _ = try connection.receive(stream, [], fin: true)
                try connection.respond(to: stream, HTTPResponse(status: .ok))
        }
        let retired = connection.census
        #expect(retired.trackedStreams == 0)

        // Everything still in flight for that stream when it was retired now lands.
        _ = try connection.receive(stream, Self.partialRequest(), fin: false)
        _ = try connection.receive(stream, [0x00, 0x04, 0x61, 0x62, 0x63, 0x64], fin: true)

        let after = connection.census
        #expect(after.trackedStreams == 0, "late octets rebuilt a retired stream's record")
        #expect(after.bufferedRequestBodyBytes == 0)
        #expect(after.blockedSections == 0)
        // And they cost the peer nothing extra either — no second charge for a stream already gone.
        #expect(after.chargedStreamResets == retired.chargedStreamResets)
    }

    @Test("an explicit registration cannot resurrect a retired stream either")
    func registerStreamCannotResurrectARetiredStream() throws {
        var connection = HTTP3Connection()
        let stream = QUICStreamID(4)

        _ = try connection.receive(stream, Self.partialRequest(), fin: false)
        _ = connection.resetStream(stream, errorCode: 0x010C)
        #expect(connection.census.trackedStreams == 0)

        connection.registerStream(stream, direction: .bidirectional)

        #expect(connection.census.trackedStreams == 0)
    }

    @Test("a stream above the retired run is still perfectly serviceable")
    func aFreshStreamAboveTheWatermarkStillWorks() throws {
        var connection = HTTP3Connection()

        _ = try connection.receive(QUICStreamID(0), Self.partialRequest(), fin: false)
        _ = connection.resetStream(QUICStreamID(0), errorCode: 0x010C)

        // The next request the peer opens is numbered above the retired one (RFC 9000 §2.1), so the
        // run must not touch it — a bound that refused new work would be worse than the leak.
        let events = try connection.receive(QUICStreamID(4), Self.completeRequest(), fin: true)

        #expect(connection.census.trackedStreams == 1)
        guard case .request(let id, let request, _) = events.first else {
            Issue.record("the fresh stream produced no request: \(events)")
            return
        }
        #expect(id == QUICStreamID(4))
        #expect(request.path == "/")
    }

    @Test("a lower-numbered stream that has not spoken yet survives a higher retirement")
    func aSilentLowerStreamSurvivesAHigherRetirement() throws {
        var connection = HTTP3Connection()

        // Stream 4 runs to completion while stream 0 has been QUIC-opened but has sent nothing yet —
        // the ordinary shape of two concurrent requests whose octets interleave. A bare "highest
        // retired id" watermark covers 0 here and silently drops its request; the run of retired ids
        // has to start at 0 and grow by one stride, so 4 waits out of band until 0 joins it.
        _ = try connection.receive(QUICStreamID(4), Self.completeRequest(), fin: true)
        try connection.respond(to: QUICStreamID(4), HTTPResponse(status: .ok))
        #expect(connection.census.trackedStreams == 0)

        let events = try connection.receive(QUICStreamID(0), Self.completeRequest(), fin: true)

        guard case .request(let id, _, _) = events.first else {
            Issue.record("stream 0 was refused by the retirement of a higher stream: \(events)")
            return
        }
        #expect(id == QUICStreamID(0))
    }

    @Test("the run closes up once the gap is retired, and stays terminal")
    func theRetiredRunClosesOverGaps() throws {
        var connection = HTTP3Connection()

        _ = try connection.receive(QUICStreamID(8), Self.partialRequest(), fin: false)
        _ = connection.resetStream(QUICStreamID(8), errorCode: 0x010C)
        _ = try connection.receive(QUICStreamID(0), Self.partialRequest(), fin: false)
        _ = connection.resetStream(QUICStreamID(0), errorCode: 0x010C)
        // 4 is the gap: retiring it joins 0 and 8 into one run, so all three are terminal.
        _ = try connection.receive(QUICStreamID(4), Self.partialRequest(), fin: false)
        _ = connection.resetStream(QUICStreamID(4), errorCode: 0x010C)
        #expect(connection.census.trackedStreams == 0)

        for id in [QUICStreamID(0), QUICStreamID(4), QUICStreamID(8)] {
            _ = try connection.receive(id, Self.partialRequest(), fin: false)
        }

        #expect(connection.census.trackedStreams == 0)
        #expect(connection.census.bufferedRequestBodyBytes == 0)
    }

    @Test("a still-tracked lower-numbered stream is untouched by a higher retirement")
    func aLiveLowerStreamSurvivesAHigherRetirement() throws {
        var connection = HTTP3Connection()

        // Two concurrent uploads; the higher-numbered one finishes and is retired first.
        _ = try connection.receive(QUICStreamID(0), Self.partialRequest(), fin: false)
        _ = try connection.receive(QUICStreamID(4), Self.partialRequest(), fin: false)
        _ = connection.resetStream(QUICStreamID(4), errorCode: 0x010C)
        #expect(connection.census.trackedStreams == 1)

        // Stream 0 is *below* the watermark but still has a record, so its body keeps flowing: the
        // watermark refuses resurrection, never continuation.
        _ = try connection.receive(QUICStreamID(0), Self.dataFrame(), fin: false)

        #expect(connection.census.trackedStreams == 1)
        #expect(connection.census.bufferedRequestBodyBytes > 32)
    }

    // MARK: - Fixtures

    /// A complete HEADERS frame followed by a DATA prefix and no FIN (RFC 9114 §4.1).
    private static func partialRequest() -> [UInt8] {
        Self.headersFrame() + Self.dataFrame()
    }

    /// A complete HEADERS frame with no body.
    private static func completeRequest() -> [UInt8] {
        Self.headersFrame()
    }

    private static func headersFrame() -> [UInt8] {
        let section = QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: "GET"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "example.com"),
                HeaderField(name: ":path", value: "/")
            ])
        var out: [UInt8] = []
        QUICVarint.encode(0x01, into: &out)
        QUICVarint.encode(UInt64(section.count), into: &out)
        out.append(contentsOf: section)
        return out
    }

    private static func dataFrame() -> [UInt8] {
        let body = [UInt8](repeating: 0x61, count: 32)
        var out: [UInt8] = []
        QUICVarint.encode(0x00, into: &out)
        QUICVarint.encode(UInt64(body.count), into: &out)
        out.append(contentsOf: body)
        return out
    }
}
