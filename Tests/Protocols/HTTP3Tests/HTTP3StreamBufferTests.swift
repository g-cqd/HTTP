//
//  HTTP3StreamBufferTests.swift
//  HTTP3Tests
//
//  RFC 9114 §6 — the per-stream rolling receive buffers. `removeFirst(consumed)` after every drain gave
//  two things for free: a buffer that never retained a dead prefix, and a frame that could never
//  straddle a compaction because compaction happened only between frames. A read cursor keeps the
//  second by construction and must be MADE to keep the first — a cursor that never compacts is a leak
//  (audit CR-F18). These cases pin both, on the control stream, the QPACK streams and a request
//  stream, and check that a frame whose payload spans a compaction still assembles byte-identically.
//

import HTTPCore
import Testing

@testable import HTTP3

@Suite("RFC 9114 §6 — the rolling stream buffers")
struct HTTP3StreamBufferTests: HTTP3WireFixtures {
    private static let controlStream = QUICStreamID(3)
    private static let encoderStream = QUICStreamID(7)
    private static let decoderStream = QUICStreamID(11)
    private static let requestStream = QUICStreamID(0)

    /// A connection whose peer control and QPACK streams are open and past their preambles.
    private func opened() throws -> HTTP3Connection {
        var connection = HTTP3Connection()
        _ = connection.outbound()
        _ = try connection.receive(Self.controlStream, controlPreamble(), fin: false)
        _ = try connection.receive(Self.encoderStream, [0x02], fin: false)
        _ = try connection.receive(Self.decoderStream, [0x03], fin: false)
        _ = connection.outbound()
        return connection
    }

    @Test("a control stream's buffer retains neither octets nor capacity across a long connection")
    func controlStreamBufferStaysBounded() throws {
        var connection = try opened()
        // A §9 GREASE frame: a type the peer may send at any time and a receiver must ignore.
        let chunk = frame(HTTP3FrameType(rawValue: 0x21), h3Ramp(2_048))
        _ = try connection.receive(Self.controlStream, chunk, fin: false)
        let settled = connection.streams[Self.controlStream]?.buffer.capacity
        var index = 0
        while index < 512 {
            _ = try connection.receive(Self.controlStream, chunk, fin: false)
            index += 1
        }
        let state = connection.streams[Self.controlStream]
        #expect(state?.pendingOctets == 0)
        #expect(state?.bufferStart == 0)
        #expect(state?.buffer.isEmpty == true)
        #expect(state?.buffer.capacity == settled)
    }

    @Test("a chunk that always ends mid-frame does not make the buffer grow either")
    func controlStreamBufferStaysBoundedWithARemainder() throws {
        var connection = try opened()
        let whole = frame(HTTP3FrameType(rawValue: 0x21), h3Ramp(1_024))
        let head = Array(whole.prefix(600))
        let tail = Array(whole.dropFirst(600))
        _ = try connection.receive(Self.controlStream, head, fin: false)
        var index = 0
        while index < 512 {
            _ = try connection.receive(Self.controlStream, tail, fin: false)
            _ = try connection.receive(Self.controlStream, head, fin: false)
            index += 1
        }
        let state = connection.streams[Self.controlStream]
        #expect(state?.pendingOctets == head.count)
        #expect(state.map { $0.buffer.capacity <= 64 * 1_024 } == true)
    }

    @Test("a request stream's DATA spanning a compaction assembles byte-identically")
    func requestBodySpanningACompactionIsUnchanged() throws {
        var connection = try opened()
        var wire = frame(.headers, requestFieldSection(method: "POST", path: "/upload"))
        var expected: [UInt8] = []
        // Enough consumed prefix to push the read cursor past the compaction threshold, so the
        // partial frame that follows is memmoved to the front of the buffer mid-flight.
        var index = 0
        while index < 20 {
            let chunk = h3Ramp(1_024)
            wire.append(contentsOf: frame(.data, chunk))
            expected.append(contentsOf: chunk)
            index += 1
        }
        let straddling = h3Ramp(2_048)
        let last = frame(.data, straddling)
        expected.append(contentsOf: straddling)
        _ = try connection.receive(Self.requestStream, wire + last.prefix(700), fin: false)
        // The compaction happened: the straddling frame's prefix was moved to the front.
        #expect(connection.streams[Self.requestStream]?.bufferStart == 0)
        let events = try connection.receive(
            Self.requestStream, Array(last.dropFirst(700)), fin: true
        )
        guard case .request(_, _, let body) = events.first else {
            Issue.record("expected a completed request, got \(events)")
            return
        }
        #expect(body == expected)
    }

    @Test(
        "a request split at every offset arrives byte-identically",
        arguments: [1, 2, 3, 8, 32, 96, 300]
    )
    func aRequestSplitAtAnyOffsetIsUnchanged(_ split: Int) throws {
        var connection = try opened()
        let payload = h3Ramp(512)
        let wire =
            frame(.headers, requestFieldSection(method: "POST", path: "/upload"))
            + frame(.data, payload)
        var events = try connection.receive(
            Self.requestStream, Array(wire.prefix(split)), fin: false
        )
        events += try connection.receive(
            Self.requestStream, Array(wire.dropFirst(split)), fin: true
        )
        guard case .request(let streamID, _, let body) = events.first else {
            Issue.record("expected a completed request, got \(events)")
            return
        }
        #expect(streamID == Self.requestStream)
        #expect(body == payload)
    }

    @Test("a stream-type varint split across two chunks still classifies the stream")
    func splitStreamTypeVarintStillClassifies() throws {
        var connection = HTTP3Connection()
        _ = connection.outbound()
        // A 2-octet varint stream type (0x40 0x00 == 0), fed one octet at a time: the first chunk must
        // leave the cursor untouched so the second can complete it (RFC 9000 §16 / RFC 9114 §6.2).
        _ = try connection.receive(Self.controlStream, [0x40], fin: false)
        #expect(connection.streams[Self.controlStream]?.bufferStart == 0)
        #expect(connection.streams[Self.controlStream]?.pendingOctets == 1)
        _ = try connection.receive(
            Self.controlStream, [0x00] + frame(.settings, settingsPayload([(0x01, 0)])), fin: false
        )
        #expect(connection.peerControlStream == Self.controlStream)
        #expect(connection.peerSettingsReceived)
        #expect(connection.streams[Self.controlStream]?.pendingOctets == 0)
    }
}
