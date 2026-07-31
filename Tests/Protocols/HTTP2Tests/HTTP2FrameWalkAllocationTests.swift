//
//  HTTP2FrameWalkAllocationTests.swift
//  HTTP2Tests
//
//  RFC 9113 §4.1 — what the borrowed frame walk costs, stated as properties rather than constants.
//  The owning decoder materializes one `[UInt8]` per frame, so its cost scales with BOTH the frame
//  count and the payload size; the borrowed walk returns a range into the caller's buffer, so it
//  scales with neither. Allocation COUNT alone cannot see the second half — a re-introduced copy that
//  moves the count by a constant hides there — which is why the octet slope is asserted too
//  (`HeaderParserAllocationTests` is the model). Audit CR-F18.
//
//  NOTE: the counts below are exact and deterministic; the wall-clock claims in the commit bodies are
//  NOT, because this host ran concurrent agent workloads throughout.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP2

/// `count` back-to-back DATA frames of `size` payload octets each (RFC 9113 §6.1).
private func dataFrames(count: Int, size: Int) -> [UInt8] {
    var wire: [UInt8] = []
    let payload = ramp(size)
    var index = 0
    while index < count {
        wire.append(
            contentsOf: H2WireFrame(
                label: "DATA",
                type: 0x00,
                flags: 0x00,
                stream: 1,
                payload: payload
            )
            .encoded
        )
        index += 1
    }
    return wire
}

/// Drains `wire` with the owning decoder, returning the octets it decoded.
private func drainOwning(_ wire: [UInt8]) -> Int {
    let decoder = HTTP2FrameDecoder()
    return wire.withUnsafeBytes { raw in
        var reader = ByteReader(raw)
        var total = 0
        while let frame = try? decoder.nextFrame(&reader) {
            total &+= frame.payload.count
        }
        return total
    }
}

/// Drains `wire` with the borrowed walk, reading each payload in place.
private func drainBorrowed(_ wire: [UInt8]) -> Int {
    let decoder = HTTP2FrameDecoder()
    return wire.withUnsafeBytes { raw in
        var reader = ByteReader(raw)
        var total = 0
        // Index-based `while` over the cursor, never a `for-in` over a span-derived sequence — the
        // shape `MultipartParser` uses, kept so the debug-build oracles here measure the decode and
        // not `IndexingIterator.next()` (task #29 sweep).
        while let framing = try? decoder.nextFrameRange(&reader) {
            let view = HTTP2FrameView(
                header: framing.header,
                payload: reader.slice(in: framing.payload)
            )
            total &+= view.payload.byteCount
        }
        return total
    }
}

@Test("the borrowed walk allocates nothing at all — no payload leaves the buffer it arrived in")
func borrowedWalkAllocatesNothing() {
    let wire = dataFrames(count: 32, size: 1_024)
    _ = drainBorrowed(wire)  // warm up: lazy init is not charged to the measurement
    guard let borrowed = mallocDelta({ _ = drainBorrowed(wire) }) else {
        return  // allocation counting is unavailable on this platform
    }
    // The floor, and it is zero: a frame is a header (a POD value) plus a range into the caller's
    // buffer. Nothing is boxed, nothing is copied, nothing escapes.
    #expect(borrowed == 0)
}

@Test("the owning decoder allocates once per frame, and the borrowed walk does not")
func owningDecoderAllocatesPerFrame() {
    let few = dataFrames(count: 8, size: 1_024)
    let many = dataFrames(count: 32, size: 1_024)
    _ = drainOwning(few)
    _ = drainOwning(many)
    _ = drainBorrowed(few)
    _ = drainBorrowed(many)
    guard let owningFew = mallocDelta({ _ = drainOwning(few) }),
        let owningMany = mallocDelta({ _ = drainOwning(many) }),
        let borrowedFew = mallocDelta({ _ = drainBorrowed(few) }),
        let borrowedMany = mallocDelta({ _ = drainBorrowed(many) })
    else {
        return  // allocation counting is unavailable on this platform
    }
    // The slope is the claim, not the intercept: 24 more frames cost the owning decoder 24 more
    // allocations, and the borrowed walk none. Measured 8 → 32 / 32 → 0.
    #expect(owningMany - owningFew == 24)
    #expect(borrowedMany - borrowedFew == 0)
}

@Test("the borrowed walk's heap traffic does not grow with the payload size; the owning one's does")
func borrowedWalkOctetsAreSizeIndependent() {
    let narrowWire = dataFrames(count: 16, size: 256)
    let wideWire = dataFrames(count: 16, size: 4_096)
    _ = drainOwning(narrowWire)
    _ = drainOwning(wideWire)
    _ = drainBorrowed(narrowWire)
    _ = drainBorrowed(wideWire)
    guard let owningNarrow = mallocByteDelta({ _ = drainOwning(narrowWire) }),
        let owningWide = mallocByteDelta({ _ = drainOwning(wideWire) }),
        let borrowedNarrow = mallocByteDelta({ _ = drainBorrowed(narrowWire) }),
        let borrowedWide = mallocByteDelta({ _ = drainBorrowed(wideWire) })
    else {
        return  // allocation counting is unavailable on this platform
    }
    let wireGrowth = wideWire.count - narrowWire.count
    // The owning decoder copies every octet it decodes: its heap traffic tracks the wire.
    #expect(owningWide - owningNarrow >= wireGrowth)
    // The borrowed walk copies none of them, at either size.
    #expect(borrowedWide == borrowedNarrow)
    #expect(borrowedWide == 0)
}
