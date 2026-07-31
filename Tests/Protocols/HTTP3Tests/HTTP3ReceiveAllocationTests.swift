//
//  HTTP3ReceiveAllocationTests.swift
//  HTTP3Tests
//
//  RFC 9114 §6 — the allocation budget of the connection's INBOUND path, the half the response-encode
//  oracle never covered. Every frame a peer sent used to cost a fresh `[UInt8]` of its payload before
//  the engine had looked at the type, and every drain used to `removeFirst` a buffer the stream table
//  still shared — a memmove AND a copy-on-write copy of the whole thing. So a flood of frames RFC 9114
//  §9 requires be *ignored* still allocated, several times, per frame. The properties below are
//  per-frame and per-octet slopes rather than ceilings: a re-introduced copy that shifts a count by a
//  constant hides from a ceiling, and one that only copies large payloads hides from a count entirely.
//  Audit CR-F18.
//
//  These counts are exact and deterministic (libmalloc hook, per measuring thread). Timing claims in
//  the commit bodies are NOT — this host ran concurrent agent workloads throughout.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP3

@Suite("RFC 9114 §6 — inbound allocation budget")
struct HTTP3ReceiveAllocationTests: HTTP3WireFixtures {
    private static let controlStream = QUICStreamID(3)
    private static let requestStream = QUICStreamID(0)

    /// A connection whose peer control and QPACK streams are open and past their preambles.
    private func opened() throws -> HTTP3Connection {
        var connection = HTTP3Connection()
        _ = connection.outbound()
        _ = try connection.receive(Self.controlStream, controlPreamble(), fin: false)
        _ = try connection.receive(QUICStreamID(7), [0x02], fin: false)
        _ = try connection.receive(QUICStreamID(11), [0x03], fin: false)
        _ = connection.outbound()
        return connection
    }

    /// `count` §9 GREASE frames of `size` payload octets — a receiver must ignore them.
    private func greaseWire(count: Int, size: Int) -> [UInt8] {
        var wire: [UInt8] = []
        let one = frame(HTTP3FrameType(rawValue: 0x21), h3Ramp(size))
        var index = 0
        while index < count {
            wire.append(contentsOf: one)
            index += 1
        }
        return wire
    }

    /// Feeds `wire` to a warmed control stream repeatedly, returning one steady-state receive's cost.
    private func steadyStateCost(of wire: [UInt8]) throws -> (allocations: Int, octets: Int)? {
        var connection = try opened()
        var index = 0
        while index < 4 {
            _ = try connection.receive(Self.controlStream, wire, fin: false)
            index += 1
        }
        guard
            let allocations = mallocDelta({
                _ = try? connection.receive(Self.controlStream, wire, fin: false)
            }),
            let octets = mallocByteDelta({
                _ = try? connection.receive(Self.controlStream, wire, fin: false)
            })
        else {
            return nil
        }
        return (allocations, octets)
    }

    @Test("ignoring an unknown frame costs nothing per frame, at any payload size (§9)")
    func ignoredFramesCostNothingPerFrame() throws {
        guard let few = try steadyStateCost(of: greaseWire(count: 8, size: 1_024)),
            let many = try steadyStateCost(of: greaseWire(count: 32, size: 1_024)),
            let wide = try steadyStateCost(of: greaseWire(count: 8, size: 8_192))
        else {
            return  // allocation counting is unavailable on this platform
        }
        // Three slopes, all of which must be flat. 24 more frames: no more allocations. Eight times
        // the payload: no more allocations and no more heap octets. A peer cannot make the server
        // allocate by sending frames it is required to throw away — which it previously could, at
        // roughly 3 allocations and 3.7 KiB per 1 KiB frame.
        #expect(many.allocations == few.allocations)
        #expect(wide.allocations == few.allocations)
        #expect(wide.octets == few.octets)
        #expect(few.allocations == 0)
        #expect(few.octets == 0)
    }

    @Test("a buffered request body is copied ONCE into the body, not three times over")
    func bufferedBodyOctetsScaleAtOnce() throws {
        guard let narrow = try bufferedBodyOctets(bodySize: 1_024),
            let wide = try bufferedBodyOctets(bodySize: 16_384)
        else {
            return  // allocation counting is unavailable on this platform
        }
        // The octet SLOPE, which a count-only oracle cannot see. A buffered body is appended to the
        // stream's rolling buffer and then to the request body: two touches of every octet, so ~2x.
        // It was ~4.25x — the extra two-and-a-quarter were the decoder's throwaway `[UInt8]` of the
        // payload plus the `removeFirst` copy-on-write copy of the whole shared buffer. Measured
        // 4.25x before, 2.00x after; the 3x threshold sits between them, and is a slope so there is
        // no constant to re-tune.
        let growth = wide - narrow
        #expect(growth < (16_384 - 1_024) * 3)
        #expect(growth > 16_384 - 1_024)  // it does not go DOWN either: the body is still buffered
    }

    /// The heap octets one buffered DATA frame of `bodySize` costs on an open request stream.
    private func bufferedBodyOctets(bodySize: Int) throws -> Int? {
        var connection = try opened()
        _ = try connection.receive(
            Self.requestStream,
            frame(.headers, requestFieldSection(method: "POST", path: "/upload")),
            fin: false
        )
        _ = connection.outbound()
        let wire = frame(.data, h3Ramp(bodySize))
        return mallocByteDelta {
            _ = try? connection.receive(Self.requestStream, wire, fin: false)
        }
    }
}
