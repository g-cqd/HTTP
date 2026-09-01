//
//  HTTP3FrameWalkTests.swift
//  HTTP3Tests
//
//  RFC 9114 §7.1 — the borrowed frame walk must frame a stream EXACTLY as the owning decoder does.
//  `nextFrameRange` is the implementation `nextFrame` copies from, so the two cannot diverge by
//  construction; these cases pin that as an observable property anyway, across the §7.2 frame-type
//  matrix (including a reserved HTTP/2 type and a GREASE type §9 requires be ignored), across every
//  chunk boundary a frame can be split on — a QUIC stream delivers whatever it delivers — and across
//  the multi-byte varint Length encodings. Audit CR-F18.
//
//  The allocation cases below state the cost as SLOPES: the owning decoder's cost scales with both the
//  frame count and the payload size, the borrowed walk's with neither. A count-only ceiling cannot see
//  a re-introduced copy that shifts the count by a constant; the octet slope can.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP3

/// A payload whose octets depend on their position, so a shifted or truncated copy is visible.
func h3Ramp(_ count: Int) -> [UInt8] {
    var out: [UInt8] = []
    out.reserveCapacity(count)
    var index = 0
    while index < count {
        out.append(UInt8((index &* 31 &+ 7) & 0xFF))
        index += 1
    }
    return out
}

/// One RFC 9114 §7.1 frame on the wire: varint Type, varint Length, payload.
struct H3WireFrame: Sendable, CustomStringConvertible {
    let label: String
    let type: UInt64
    let payload: [UInt8]

    var description: String { label }

    var encoded: [UInt8] {
        var out: [UInt8] = []
        QUICVarint.encode(type, into: &out)
        QUICVarint.encode(UInt64(payload.count), into: &out)
        out.append(contentsOf: payload)
        return out
    }
}

/// The §7.2 frame types, the §7.2.1 reserved HTTP/2 types, a §9 GREASE type, and the empty edge.
let http3FrameMatrix: [H3WireFrame] = [
    H3WireFrame(label: "DATA/0", type: 0x00, payload: []),
    H3WireFrame(label: "DATA/1k", type: 0x00, payload: h3Ramp(1_024)),
    H3WireFrame(label: "HEADERS", type: 0x01, payload: h3Ramp(48)),
    H3WireFrame(label: "CANCEL_PUSH", type: 0x03, payload: h3Ramp(1)),
    H3WireFrame(label: "SETTINGS", type: 0x04, payload: h3Ramp(8)),
    H3WireFrame(label: "PUSH_PROMISE", type: 0x05, payload: h3Ramp(16)),
    H3WireFrame(label: "GOAWAY", type: 0x07, payload: h3Ramp(1)),
    H3WireFrame(label: "MAX_PUSH_ID", type: 0x0D, payload: h3Ramp(1)),
    H3WireFrame(label: "reserved/0x02", type: 0x02, payload: h3Ramp(4)),
    H3WireFrame(label: "reserved/0x06", type: 0x06, payload: h3Ramp(4)),
    H3WireFrame(label: "GREASE/0x21", type: 0x21, payload: h3Ramp(300)),
    H3WireFrame(label: "DATA/16k", type: 0x00, payload: h3Ramp(16_000))
]

/// Decodes `bytes` with the OWNING decoder — the reference behaviour.
private func h3OwningDecode(_ bytes: [UInt8]) throws -> [(HTTP3FrameType, [UInt8])] {
    let decoder = HTTP3FrameDecoder(maxFrameSize: 65_536)
    let result: Result<[(HTTP3FrameType, [UInt8])], HTTP3Error> = bytes.withUnsafeBytes { raw in
        Result { () throws(HTTP3Error) in
            var reader = ByteReader(raw)
            var out: [(HTTP3FrameType, [UInt8])] = []
            while let frame = try decoder.nextFrame(&reader) {
                out.append((frame.type, frame.payload))
            }
            return out
        }
    }
    return try result.get()
}

/// Decodes `bytes` with the BORROWED walk, materializing each payload only to compare it here.
private func h3BorrowedDecode(_ bytes: [UInt8]) throws -> [(HTTP3FrameType, [UInt8])] {
    let decoder = HTTP3FrameDecoder(maxFrameSize: 65_536)
    let result: Result<[(HTTP3FrameType, [UInt8])], HTTP3Error> = bytes.withUnsafeBytes { raw in
        Result { () throws(HTTP3Error) in
            var reader = ByteReader(raw)
            var out: [(HTTP3FrameType, [UInt8])] = []
            // Index-based `while` over the cursor, never a `for-in` over a span-derived sequence —
            // the shape `MultipartParser` uses, kept so the debug-build allocation oracles measure
            // the decode and not `IndexingIterator.next()` (task #29 sweep).
            while let framing = try decoder.nextFrameRange(&reader) {
                let view = HTTP3FrameView(
                    type: framing.type,
                    payload: reader.slice(in: framing.payload)
                )
                out.append((view.type, view.payload.withUnsafeBytes { Array($0) }))
            }
            return out
        }
    }
    return try result.get()
}

/// Whether two decodes agree on every frame type and every payload octet.
private func h3Agree(
    _ lhs: [(HTTP3FrameType, [UInt8])],
    _ rhs: [(HTTP3FrameType, [UInt8])]
) -> Bool {
    guard lhs.count == rhs.count else {
        return false
    }
    var index = 0
    while index < lhs.count {
        guard lhs[index].0 == rhs[index].0, lhs[index].1 == rhs[index].1 else {
            return false
        }
        index += 1
    }
    return true
}

/// The whole matrix concatenated, as one stream's worth of octets.
private func h3MatrixWire() -> [UInt8] {
    var wire: [UInt8] = []
    var index = 0
    while index < http3FrameMatrix.count {
        wire.append(contentsOf: http3FrameMatrix[index].encoded)
        index += 1
    }
    return wire
}

@Test(
    "the borrowed walk decodes each frame type byte-identically to the owning decoder",
    arguments: http3FrameMatrix
)
func h3BorrowedWalkMatchesOwningDecoder(_ frame: H3WireFrame) throws {
    let owning = try h3OwningDecode(frame.encoded)
    #expect(owning.count == 1)
    #expect(owning.first?.1 == frame.payload)
    #expect(h3Agree(owning, try h3BorrowedDecode(frame.encoded)))
}

@Test("the borrowed walk decodes the whole frame-type matrix back to back")
func h3BorrowedWalkMatchesOverTheWholeMatrix() throws {
    let wire = h3MatrixWire()
    let owning = try h3OwningDecode(wire)
    #expect(owning.count == http3FrameMatrix.count)
    #expect(h3Agree(owning, try h3BorrowedDecode(wire)))
}

@Test(
    "a frame split across a chunk boundary decodes identically at every split point",
    arguments: [1, 2, 3, 5, 17, 64, 1_000, 1_500]
)
func h3BorrowedWalkAgreesOnEverySplitPoint(_ split: Int) throws {
    let wire = h3MatrixWire()
    let prefix = Array(wire.prefix(split))
    #expect(h3Agree(try h3OwningDecode(prefix), try h3BorrowedDecode(prefix)))
    #expect(h3Agree(try h3OwningDecode(wire), try h3BorrowedDecode(wire)))
}

@Test("the borrowed walk leaves the cursor exactly where the owning decoder leaves it")
func h3BorrowedWalkConsumesTheSameOctets() throws {
    var wire = h3MatrixWire()
    wire.append(contentsOf: [0x00, 0x40])  // a trailing partial Length varint, still arriving
    let decoder = HTTP3FrameDecoder(maxFrameSize: 65_536)
    let positions: Result<(owning: Int, borrowed: Int), HTTP3Error> = wire.withUnsafeBytes { raw in
        Result { () throws(HTTP3Error) in
            var owning = ByteReader(raw)
            while try decoder.nextFrame(&owning) != nil {
                continue  // drain to the last complete frame; only the final cursor matters here
            }
            var borrowed = ByteReader(raw)
            while try decoder.nextFrameRange(&borrowed) != nil {
                continue
            }
            return (owning.position, borrowed.position)
        }
    }
    let settled = try positions.get()
    #expect(settled.owning == settled.borrowed)
    #expect(settled.borrowed == wire.count - 2)
}

@Test("the borrowed walk reports the excessive-load bound the owning decoder reports (§7.1)")
func h3BorrowedWalkRejectsAnOversizedFrame() {
    var wire: [UInt8] = []
    QUICVarint.encode(0x00, into: &wire)
    QUICVarint.encode(100_000, into: &wire)
    let decoder = HTTP3FrameDecoder(maxFrameSize: 16_384)
    let codes: (owning: HTTP3ErrorCode?, borrowed: HTTP3ErrorCode?) = wire.withUnsafeBytes { raw in
        var owning = ByteReader(raw)
        var borrowed = ByteReader(raw)
        let first = Result { () throws(HTTP3Error) in try decoder.nextFrame(&owning) }
        let second = Result { () throws(HTTP3Error) in
            try decoder.nextFrameRange(&borrowed) != nil
        }
        return (first.h3FailureCode, second.h3FailureCode)
    }
    #expect(codes.owning == .h3ExcessiveLoad)
    #expect(codes.borrowed == codes.owning)
}

extension Result where Failure == HTTP3Error {
    /// The HTTP/3 error code this result failed with, or nil if it succeeded.
    var h3FailureCode: HTTP3ErrorCode? {
        guard case .failure(let error) = self else {
            return nil
        }
        return HTTP3ErrorCode(rawValue: error.code)
    }
}

/// `count` back-to-back DATA frames of `size` payload octets each (RFC 9114 §7.2.1).
private func h3DataFrames(count: Int, size: Int) -> [UInt8] {
    var wire: [UInt8] = []
    let frame = H3WireFrame(label: "DATA", type: 0x00, payload: h3Ramp(size)).encoded
    var index = 0
    while index < count {
        wire.append(contentsOf: frame)
        index += 1
    }
    return wire
}

/// Drains `wire` with the owning decoder, returning the octets it decoded.
private func h3DrainOwning(_ wire: [UInt8]) -> Int {
    let decoder = HTTP3FrameDecoder(maxFrameSize: 65_536)
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
private func h3DrainBorrowed(_ wire: [UInt8]) -> Int {
    let decoder = HTTP3FrameDecoder(maxFrameSize: 65_536)
    return wire.withUnsafeBytes { raw in
        var reader = ByteReader(raw)
        var total = 0
        while let framing = try? decoder.nextFrameRange(&reader) {
            total &+= reader.slice(in: framing.payload).byteCount
        }
        return total
    }
}

@Test("the borrowed walk allocates nothing at all — no payload leaves the buffer it arrived in")
func h3BorrowedWalkAllocatesNothing() {
    let wire = h3DataFrames(count: 32, size: 1_024)
    _ = h3DrainBorrowed(wire)  // warm up: lazy init is not charged to the measurement
    guard let borrowed = mallocDelta({ _ = h3DrainBorrowed(wire) }) else {
        return  // allocation counting is unavailable on this platform
    }
    #expect(borrowed == 0)
}

@Test("the owning decoder allocates once per frame and per octet; the borrowed walk neither")
func h3OwningDecoderAllocatesPerFrame() {
    let few = h3DataFrames(count: 8, size: 1_024)
    let many = h3DataFrames(count: 32, size: 1_024)
    let wide = h3DataFrames(count: 8, size: 8_192)
    _ = h3DrainOwning(few)
    _ = h3DrainOwning(many)
    _ = h3DrainOwning(wide)
    _ = h3DrainBorrowed(few)
    _ = h3DrainBorrowed(many)
    guard let owningFew = mallocDelta({ _ = h3DrainOwning(few) }),
        let owningMany = mallocDelta({ _ = h3DrainOwning(many) }),
        let owningNarrowOctets = mallocByteDelta({ _ = h3DrainOwning(few) }),
        let owningWideOctets = mallocByteDelta({ _ = h3DrainOwning(wide) }),
        let borrowedFew = mallocDelta({ _ = h3DrainBorrowed(few) }),
        let borrowedMany = mallocDelta({ _ = h3DrainBorrowed(many) })
    else {
        return  // allocation counting is unavailable on this platform
    }
    // Slopes, not intercepts: 24 more frames cost the owning decoder 24 more allocations and the
    // borrowed walk none; 7× more payload costs the owning decoder proportionally more heap traffic.
    #expect(owningMany - owningFew == 24)
    #expect(borrowedMany - borrowedFew == 0)
    #expect(owningWideOctets - owningNarrowOctets >= wide.count - few.count)
}
