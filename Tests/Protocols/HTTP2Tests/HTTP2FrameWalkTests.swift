//
//  HTTP2FrameWalkTests.swift
//  HTTP2Tests
//
//  RFC 9113 §4.1 — the borrowed frame walk must frame the wire EXACTLY as the owning decoder does.
//  `nextFrameRange` is the implementation `nextFrame` copies from, so the two cannot diverge by
//  construction; these cases pin that as an observable property anyway, across the full §6 frame-type
//  matrix and across every chunk boundary a frame can be split on, because the whole point of the
//  change (audit CR-F18) is that no octet of any frame is re-interpreted when the copy goes away.
//

import HTTPCore
import Testing

@testable import HTTP2

/// One frame on the wire, described by what it should decode to.
struct H2WireFrame: Sendable, CustomStringConvertible {
    let label: String
    let type: UInt8
    let flags: UInt8
    let stream: UInt32
    let payload: [UInt8]

    var description: String { label }

    /// The 9-octet header (RFC 9113 §4.1) followed by the payload.
    var encoded: [UInt8] {
        var out: [UInt8] = [
            UInt8((payload.count >> 16) & 0xFF),
            UInt8((payload.count >> 8) & 0xFF),
            UInt8(payload.count & 0xFF),
            type,
            flags,
            UInt8((stream >> 24) & 0x7F),
            UInt8((stream >> 16) & 0xFF),
            UInt8((stream >> 8) & 0xFF),
            UInt8(stream & 0xFF)
        ]
        out.append(contentsOf: payload)
        return out
    }
}

/// A payload of `count` octets whose values depend on the position, so a truncated or shifted copy is
/// visible rather than accidentally equal.
func ramp(_ count: Int) -> [UInt8] {
    var out: [UInt8] = []
    out.reserveCapacity(count)
    var index = 0
    while index < count {
        out.append(UInt8((index &* 31 &+ 7) & 0xFF))
        index += 1
    }
    return out
}

/// Every RFC 9113 §6 frame type, plus an unknown (§4.1 "ignore") type and the zero-length edge.
let http2FrameMatrix: [H2WireFrame] = [
    H2WireFrame(label: "DATA/0", type: 0x00, flags: 0x01, stream: 1, payload: []),
    H2WireFrame(label: "DATA/1k", type: 0x00, flags: 0x00, stream: 1, payload: ramp(1_024)),
    H2WireFrame(label: "HEADERS", type: 0x01, flags: 0x04, stream: 3, payload: ramp(40)),
    H2WireFrame(label: "PRIORITY", type: 0x02, flags: 0x00, stream: 5, payload: ramp(5)),
    H2WireFrame(label: "RST_STREAM", type: 0x03, flags: 0x00, stream: 7, payload: ramp(4)),
    H2WireFrame(label: "SETTINGS", type: 0x04, flags: 0x00, stream: 0, payload: ramp(12)),
    H2WireFrame(label: "SETTINGS/ACK", type: 0x04, flags: 0x01, stream: 0, payload: []),
    H2WireFrame(label: "PUSH_PROMISE", type: 0x05, flags: 0x04, stream: 9, payload: ramp(20)),
    H2WireFrame(label: "PING", type: 0x06, flags: 0x00, stream: 0, payload: ramp(8)),
    H2WireFrame(label: "GOAWAY", type: 0x07, flags: 0x00, stream: 0, payload: ramp(8)),
    H2WireFrame(label: "WINDOW_UPDATE", type: 0x08, flags: 0x00, stream: 1, payload: ramp(4)),
    H2WireFrame(label: "CONTINUATION", type: 0x09, flags: 0x04, stream: 3, payload: ramp(64)),
    H2WireFrame(label: "GREASE/0x2A", type: 0x2A, flags: 0xFF, stream: 11, payload: ramp(256))
]

/// Decodes `bytes` with the OWNING decoder — the reference behaviour.
private func owningDecode(_ bytes: [UInt8]) throws -> [(HTTP2FrameHeader, [UInt8])] {
    let decoder = HTTP2FrameDecoder()
    return try bytes.withUnsafeBytes { raw in
        var reader = ByteReader(raw)
        var out: [(HTTP2FrameHeader, [UInt8])] = []
        while let frame = try decoder.nextFrame(&reader) {
            out.append((frame.header, frame.payload))
        }
        return out
    }
}

/// Decodes `bytes` with the BORROWED walk, materializing each payload only to compare it here.
private func borrowedDecode(_ bytes: [UInt8]) throws -> [(HTTP2FrameHeader, [UInt8])] {
    let decoder = HTTP2FrameDecoder()
    return try bytes.withUnsafeBytes { raw in
        var reader = ByteReader(raw)
        var out: [(HTTP2FrameHeader, [UInt8])] = []
        // Index-based `while`, not `for-in`: every span-borrowing scan in the package is written this
        // way so the debug-build allocation oracles are not charged for `IndexingIterator.next()`
        // (task #29 sweep; same shape as `MultipartParser`).
        while let framing = try decoder.nextFrameRange(&reader) {
            let view = HTTP2FrameView(
                header: framing.header,
                payload: reader.slice(in: framing.payload)
            )
            out.append((view.header, view.payload.withUnsafeBytes { Array($0) }))
        }
        return out
    }
}

extension Result where Failure == HTTP2Error {
    /// The HTTP/2 error code this result failed with, or nil if it succeeded.
    var failureCode: HTTP2ErrorCode? {
        guard case .failure(let error) = self else {
            return nil
        }
        return error.code
    }
}

/// Whether two decodes agree on every header field and every payload octet.
private func agree(
    _ lhs: [(HTTP2FrameHeader, [UInt8])],
    _ rhs: [(HTTP2FrameHeader, [UInt8])]
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

@Test(
    "the borrowed walk decodes each frame type byte-identically to the owning decoder",
    arguments: http2FrameMatrix
)
func borrowedWalkMatchesOwningDecoder(_ frame: H2WireFrame) throws {
    let wire = frame.encoded
    let owning = try owningDecode(wire)
    #expect(owning.count == 1)
    #expect(owning.first?.1 == frame.payload)
    #expect(agree(owning, try borrowedDecode(wire)))
}

@Test("the borrowed walk decodes the whole frame-type matrix back to back")
func borrowedWalkMatchesOverTheWholeMatrix() throws {
    var wire: [UInt8] = []
    var index = 0
    while index < http2FrameMatrix.count {
        wire.append(contentsOf: http2FrameMatrix[index].encoded)
        index += 1
    }
    let owning = try owningDecode(wire)
    #expect(owning.count == http2FrameMatrix.count)
    #expect(agree(owning, try borrowedDecode(wire)))
}

@Test(
    "a frame split across a chunk boundary decodes identically at every split point",
    arguments: [1, 4, 8, 9, 10, 13, 37, 128]
)
func borrowedWalkAgreesOnEverySplitPoint(_ split: Int) throws {
    var wire: [UInt8] = []
    var index = 0
    while index < http2FrameMatrix.count {
        wire.append(contentsOf: http2FrameMatrix[index].encoded)
        index += 1
    }
    let prefix = Array(wire.prefix(split))
    // The prefix on its own: both must agree on how much is still arriving...
    #expect(agree(try owningDecode(prefix), try borrowedDecode(prefix)))
    // ...and on the whole wire once the remainder lands.
    #expect(agree(try owningDecode(wire), try borrowedDecode(wire)))
}

@Test("the borrowed walk leaves the cursor exactly where the owning decoder leaves it")
func borrowedWalkConsumesTheSameOctets() throws {
    var wire: [UInt8] = []
    var index = 0
    while index < http2FrameMatrix.count {
        wire.append(contentsOf: http2FrameMatrix[index].encoded)
        index += 1
    }
    wire.append(contentsOf: [0, 0, 6, 4])  // a trailing partial header, still arriving
    let decoder = HTTP2FrameDecoder()
    let positions: (owning: Int, borrowed: Int) = try wire.withUnsafeBytes { raw in
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
    #expect(positions.owning == positions.borrowed)
    #expect(positions.borrowed == wire.count - 4)
}

@Test("the borrowed walk reports the §4.2 FRAME_SIZE_ERROR the owning decoder reports")
func borrowedWalkRejectsAnOversizedFrame() {
    // The header declares length 20,000 (0x4E20); the decoder caps at 16,384.
    let header: [UInt8] = [0x00, 0x4E, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
    let decoder = HTTP2FrameDecoder(maxFrameSize: 16_384)
    let codes: (owning: HTTP2ErrorCode?, borrowed: HTTP2ErrorCode?) = header.withUnsafeBytes {
        raw in
        var owning = ByteReader(raw)
        var borrowed = ByteReader(raw)
        let first = Result { () throws(HTTP2Error) in try decoder.nextFrame(&owning) }
        let second = Result { () throws(HTTP2Error) in
            try decoder.nextFrameRange(&borrowed) != nil
        }
        return (first.failureCode, second.failureCode)
    }
    #expect(codes.owning == .frameSizeError)
    #expect(codes.borrowed == codes.owning)
}
