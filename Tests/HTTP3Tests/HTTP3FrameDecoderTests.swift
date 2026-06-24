//
//  HTTP3FrameDecoderTests.swift
//  HTTP3Tests
//
//  RED→GREEN driver for the RFC 9114 §7.1 frame layer (varint Type + varint Length + payload): single
//  and back-to-back frames, multi-byte varint lengths, incremental "need more bytes" behavior, the
//  excessive-load bound, and the §7.2.1 reserved-HTTP/2 frame-type classification.
//

import HTTPCore
import Testing

@testable import HTTP3

@Suite("RFC 9114 §7.1 — HTTP/3 frame decoder")
struct HTTP3FrameDecoderTests {
    private func frame(type: UInt64, payload: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        QUICVarint.encode(type, into: &out)
        QUICVarint.encode(UInt64(payload.count), into: &out)
        out.append(contentsOf: payload)
        return out
    }

    private func decodeAll(
        _ bytes: [UInt8], maxFrameSize: Int = 16_384
    ) throws -> (frames: [HTTP3FrameDecoder.Frame], consumed: Int) {
        let result: Result<(frames: [HTTP3FrameDecoder.Frame], consumed: Int), HTTP3Error> =
            bytes.withUnsafeBytes { raw in
                Result { () throws(HTTP3Error) in
                    var reader = ByteReader(raw)
                    let decoder = HTTP3FrameDecoder(maxFrameSize: maxFrameSize)
                    var frames: [HTTP3FrameDecoder.Frame] = []
                    while let next = try decoder.nextFrame(&reader) { frames.append(next) }
                    return (frames, reader.position)
                }
            }
        return try result.get()
    }

    @Test("decodes a single frame with its type and payload")
    func single() throws {
        let payload: [UInt8] = [0x01, 0x02, 0x03]
        let result = try decodeAll(frame(type: 0x01, payload: payload))
        #expect(result.frames.count == 1)
        #expect(result.frames.first?.type == .headers)
        #expect(result.frames.first?.payload == payload)
        #expect(result.consumed == 2 + payload.count)
    }

    @Test("decodes back-to-back frames in order")
    func multiple() throws {
        var bytes = frame(type: 0x01, payload: [0xAA])  // HEADERS
        bytes += frame(type: 0x00, payload: [0xBB, 0xCC])  // DATA
        let result = try decodeAll(bytes)
        #expect(result.frames.map(\.type) == [.headers, .data])
        #expect(result.frames.last?.payload == [0xBB, 0xCC])
    }

    @Test("a multi-byte varint length is honored")
    func longLength() throws {
        let payload = [UInt8](repeating: 0x5A, count: 300)  // length needs a 2-byte varint
        let result = try decodeAll(frame(type: 0x00, payload: payload))
        #expect(result.frames.first?.payload.count == 300)
    }

    @Test(
        "an incomplete frame yields no frame and consumes nothing (need more bytes)",
        arguments: [
            (label: "only the type octet", bytes: [0x01] as [UInt8]),
            (label: "type + length, no payload yet", bytes: [0x01, 0x03]),
            (label: "type + length, partial payload", bytes: [0x01, 0x03, 0xAA])
        ] as [(label: String, bytes: [UInt8])])
    func incomplete(_ testCase: (label: String, bytes: [UInt8])) throws {
        let result = try decodeAll(testCase.bytes)
        #expect(result.frames.isEmpty)
        #expect(result.consumed == 0)
    }

    @Test("a payload larger than the bound is H3_EXCESSIVE_LOAD")
    func excessiveLoad() {
        var bytes: [UInt8] = []
        QUICVarint.encode(0x00, into: &bytes)  // DATA
        QUICVarint.encode(100_000, into: &bytes)  // declared length far over the bound
        #expect {
            _ = try decodeAll(bytes, maxFrameSize: 1_000)
        } throws: { error in
            (error as? HTTP3Error)?.code == HTTP3ErrorCode.h3ExcessiveLoad.rawValue
        }
    }

    @Test("reserved HTTP/2 frame types are recognized (§7.2.1)")
    func reservedHTTP2Frames() {
        for raw: UInt64 in [0x02, 0x06, 0x08, 0x09] {
            #expect(HTTP3FrameType(rawValue: raw).isReservedHTTP2Frame)
        }
        #expect(!HTTP3FrameType.headers.isReservedHTTP2Frame)
        #expect(!HTTP3FrameType.settings.isReservedHTTP2Frame)
        // Grease types 0x1f*N+0x21 are reserved no-ops (§7.2.8).
        #expect(HTTP3FrameType(rawValue: 0x21).isGrease)
        #expect(HTTP3FrameType(rawValue: 0x21 + 0x1F).isGrease)
        #expect(!HTTP3FrameType(rawValue: 0x22).isGrease)
    }
}
