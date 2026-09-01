//
//  HTTP2ReceiveAllocationTests.swift
//  HTTP2Tests
//
//  RFC 9113 §4 — the allocation budget of the connection's INBOUND path, the half the response-encode
//  oracle never covered. Every frame a peer sends used to cost a fresh `[UInt8]` of its payload before
//  the engine had even looked at the type, so a flood of frames the RFC requires be *ignored* (§4.1
//  unknown types) still allocated once per frame. The properties below are per-frame slopes, not
//  ceilings: a re-introduced copy that shifts a count by a constant hides from a ceiling, and one that
//  copies only large payloads hides from a count. Audit CR-F18.
//
//  These counts are exact and deterministic (libmalloc hook, per measuring thread). Timing claims in
//  the commit bodies are NOT — this host ran concurrent agent workloads throughout.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP2

@Suite("RFC 9113 §4 — inbound allocation budget")
struct HTTP2ReceiveAllocationTests: HTTP2WireFixtures {
    /// A connection past the preface and the peer's SETTINGS, ready for the steady state.
    private func opened() throws -> HTTP2Connection {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()
        _ = try connection.receive(HTTP2ConnectionPreface.client + settingsFrame())
        _ = connection.outboundBytes()
        return connection
    }

    /// `count` unknown extension frames of `size` payload octets — RFC 9113 §4.1 says ignore them.
    private func greaseWire(count: Int, size: Int) -> [UInt8] {
        var wire: [UInt8] = []
        let frame = H2WireFrame(
            label: "GREASE",
            type: 0x2A,
            flags: 0x00,
            stream: 0,
            payload: ramp(size)
        )
        .encoded
        var index = 0
        while index < count {
            wire.append(contentsOf: frame)
            index += 1
        }
        return wire
    }

    /// Feeds `wire` to a warmed connection repeatedly, returning the cost of one steady-state receive.
    private func steadyStateCost(of wire: [UInt8]) throws -> (allocations: Int, octets: Int)? {
        var connection = try opened()
        var index = 0
        while index < 4 {
            _ = try connection.receive(wire)  // settle the buffer's capacity before measuring
            index += 1
        }
        guard let allocations = mallocDelta({ _ = try? connection.receive(wire) }),
            let octets = mallocByteDelta({ _ = try? connection.receive(wire) })
        else {
            return nil
        }
        return (allocations, octets)
    }

    @Test("ignoring an unknown frame costs nothing per frame, at any payload size (§4.1)")
    func ignoredFramesCostNothingPerFrame() throws {
        guard let few = try steadyStateCost(of: greaseWire(count: 8, size: 1_024)),
            let many = try steadyStateCost(of: greaseWire(count: 32, size: 1_024)),
            let wide = try steadyStateCost(of: greaseWire(count: 8, size: 8_192))
        else {
            return  // allocation counting is unavailable on this platform
        }
        // Three slopes, all of which must be flat. 24 more frames: no more allocations. Eight times
        // the payload: no more allocations and no more heap octets. A peer cannot make the server
        // allocate by sending frames it is required to throw away.
        #expect(many.allocations == few.allocations)
        #expect(wide.allocations == few.allocations)
        #expect(wide.octets == few.octets)
        #expect(few.allocations == 0)
        #expect(few.octets == 0)
    }

    /// The steady-state cost of answering `count` back-to-back PINGs (RFC 9113 §6.7).
    private func pingFloodCost(count: Int) throws -> Int? {
        var connection = try opened()
        var wire: [UInt8] = []
        var index = 0
        while index < count {
            wire.append(contentsOf: pingFrame())
            index += 1
        }
        index = 0
        while index < 4 {
            _ = try connection.receive(wire)
            _ = connection.outboundBytes()
            index += 1
        }
        let cost = mallocDelta { _ = try? connection.receive(wire) }
        _ = connection.outboundBytes()
        return cost
    }

    @Test("a PING flood is answered without materializing the opaque data (§6.7)")
    func pingAckDoesNotCopyTheOpaqueData() throws {
        guard let four = try pingFloodCost(count: 4), let sixteen = try pingFloodCost(count: 16)
        else {
            return  // allocation counting is unavailable on this platform
        }
        // The eight opaque octets are echoed from the inbound buffer straight into the outbound one
        // (RFC 9113 §6.7). What is left is the OUTBOUND buffer's own geometric growth for the ACKs,
        // which is why quadrupling the flood adds one allocation rather than quadrupling the cost —
        // the signature of "nothing is allocated per PING". Measured 4 → 4 and 16 → 5.
        #expect(sixteen <= four + 2)
        #expect(four <= 4)
    }

    @Test("a streamed request body is materialized ONCE — for the event, and not before")
    func streamedBodyIsMaterializedOnce() throws {
        var connection = HTTP2Connection { _, _ in RequestBodyPolicy(isStreaming: true) }
        _ = connection.outboundBytes()
        _ = try connection.receive(HTTP2ConnectionPreface.client + settingsFrame())
        _ = connection.outboundBytes()
        _ = try connection.receive(openStream(streamID: 1))
        _ = connection.outboundBytes()
        let chunk = dataFrame(streamID: 1, payload: ramp(4_096), endStream: false)
        var index = 0
        while index < 4 {
            _ = try connection.receive(chunk)
            _ = connection.outboundBytes()
            index += 1
        }
        guard let allocations = mallocDelta({ _ = try? connection.receive(chunk) }) else {
            return  // allocation counting is unavailable on this platform
        }
        _ = connection.outboundBytes()
        // A streaming route hands each chunk straight to the driver, so exactly one copy has to
        // exist: the event's own `[UInt8]`. The engine's intermediate copy of the frame payload is
        // what this asserts is gone — 2 allocations per chunk (the chunk and the `[Event]` carrying
        // it), not the 5 it used to be.
        #expect(allocations <= 2)
    }

    @Test("a buffered request body is copied ONCE into the body, not once per frame as well")
    func bufferedBodyOctetsScaleAtOnce() throws {
        guard let narrow = try bufferedPostOctets(bodySize: 1_024),
            let wide = try bufferedPostOctets(bodySize: 16_384)
        else {
            return  // allocation counting is unavailable on this platform
        }
        // The octet SLOPE is the claim, and a count-only oracle cannot see it. A buffered body is
        // appended to the rolling inbound buffer and then to the stream's own body: two touches of
        // every octet, so ~2x. It used to be ~3x — the third was the decoder's throwaway `[UInt8]`
        // of the frame payload. Measured 3.00x before, 2.00x after; the 2.5x threshold sits between
        // them with room on both sides, and is a slope so there is no constant to re-tune.
        let growth = wide - narrow
        #expect(growth < (16_384 - 1_024) * 5 / 2)
        #expect(growth > 16_384 - 1_024)  // it does not go DOWN either: the body is still buffered
    }

    /// The heap octets one buffered POST of `bodySize` costs, HEADERS excluded (measured on DATA).
    private func bufferedPostOctets(bodySize: Int) throws -> Int? {
        var connection = try opened()
        _ = try connection.receive(openStream(streamID: 1))
        _ = connection.outboundBytes()
        let wire = dataFrame(streamID: 1, payload: ramp(bodySize), endStream: true)
        return mallocByteDelta { _ = try? connection.receive(wire) }
    }
}
