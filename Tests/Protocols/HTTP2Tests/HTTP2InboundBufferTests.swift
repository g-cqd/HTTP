//
//  HTTP2InboundBufferTests.swift
//  HTTP2Tests
//
//  RFC 9113 §4 — the connection's rolling inbound buffer. `removeFirst(consumed)` after every drain
//  gave two things for free: a buffer that never retained a dead prefix, and a frame that could never
//  straddle a compaction because compaction happened only between frames. A read cursor keeps the
//  second by construction and must be MADE to keep the first — a cursor that never compacts is a leak
//  (audit CR-F18). These cases pin both: the live octets and the retained capacity stay bounded across
//  a long connection, and a frame whose payload spans the compaction still decodes byte-identically.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 §4 — the rolling inbound buffer")
struct HTTP2InboundBufferTests: HTTP2WireFixtures {
    /// A connection past the preface and the peer's first SETTINGS — the steady state.
    private func opened() throws -> HTTP2Connection {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()
        _ = try connection.receive(HTTP2ConnectionPreface.client + settingsFrame())
        _ = connection.outboundBytes()
        return connection
    }

    /// An unknown extension frame — RFC 9113 §4.1 requires it be ignored, payload and all.
    private func greaseFrame(size: Int) -> [UInt8] {
        H2WireFrame(label: "GREASE", type: 0x2A, flags: 0x00, stream: 0, payload: ramp(size))
            .encoded
    }

    @Test("the buffer retains neither octets nor capacity across a long connection")
    func inboundBufferStaysBounded() throws {
        var connection = try opened()
        let chunk = greaseFrame(size: 4_096)
        _ = try connection.receive(chunk)
        let settledCapacity = connection.inbound.capacity
        var index = 0
        while index < 512 {
            _ = try connection.receive(chunk)
            index += 1
        }
        // Fully drained: the cursor is reset and the live octets are gone, exactly as `removeFirst`
        // left them. This is the assertion a never-compacting cursor fails.
        #expect(connection.inbound.isEmpty)
        #expect(connection.inboundStart == 0)
        // And the storage behind them did not creep: 512 more chunks, same capacity.
        #expect(connection.inbound.capacity == settledCapacity)
    }

    @Test("a partial frame left over from each chunk does not make the buffer grow either")
    func inboundBufferStaysBoundedWithARemainder() throws {
        var connection = try opened()
        let frame = greaseFrame(size: 1_024)
        // Every chunk ends mid-frame, so the buffer always carries a remainder and never takes the
        // "fully drained" fast path — the shape that would let a cursor accumulate for ever.
        let head = Array(frame.prefix(600))
        let tail = Array(frame.dropFirst(600))
        _ = try connection.receive(head)
        var index = 0
        while index < 512 {
            _ = try connection.receive(tail)
            _ = try connection.receive(head)
            index += 1
        }
        #expect(connection.inbound.count - connection.inboundStart == head.count)
        #expect(connection.inbound.capacity <= 64 * 1_024)
    }

    @Test("a frame whose payload spans a compaction decodes byte-identically")
    func frameSpanningACompactionDecodesIdentically() throws {
        var connection = try opened()
        _ = try connection.receive(openStream(streamID: 1))
        // Enough consumed prefix to push the read cursor past the compaction threshold, so the
        // partial frame that follows is memmoved to the front of the buffer mid-flight.
        var prefix: [UInt8] = []
        var index = 0
        while index < 20 {
            prefix.append(
                contentsOf: dataFrame(streamID: 1, payload: ramp(1_024), endStream: false)
            )
            index += 1
        }
        let straddling = ramp(2_048)
        let last = dataFrame(streamID: 1, payload: straddling, endStream: true)
        _ = try connection.receive(prefix + last.prefix(700))
        #expect(connection.inboundStart == 0)  // the compaction happened
        let events = try connection.receive(Array(last.dropFirst(700)))
        guard case .request(_, _, let body) = events.first else {
            Issue.record("expected a completed request, got \(events)")
            return
        }
        var expected: [UInt8] = []
        index = 0
        while index < 20 {
            expected.append(contentsOf: ramp(1_024))
            index += 1
        }
        expected.append(contentsOf: straddling)
        #expect(body == expected)
    }

    @Test(
        "a request split at every offset arrives byte-identically",
        arguments: [1, 5, 9, 13, 64, 200, 512]
    )
    func aRequestSplitAtAnyOffsetIsUnchanged(_ split: Int) throws {
        var connection = try opened()
        let payload = ramp(700)
        let wire =
            openStream(streamID: 1)
            + dataFrame(streamID: 1, payload: payload, endStream: true)
        var events = try connection.receive(Array(wire.prefix(split)))
        events += try connection.receive(Array(wire.dropFirst(split)))
        guard case .request(let streamID, _, let body) = events.first else {
            Issue.record("expected a completed request, got \(events)")
            return
        }
        #expect(streamID == HTTP2StreamID(1))
        #expect(body == payload)
    }
}
