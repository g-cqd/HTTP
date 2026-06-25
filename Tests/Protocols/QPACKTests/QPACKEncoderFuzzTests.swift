//
//  QPACKEncoderFuzzTests.swift
//  QPACKTests
//
//  RFC 9204 §2.1.3 — the eviction-safety invariant under adversarial churn. A small table forces constant
//  eviction; the encoder inserts and references freely (blocking allowed), while a mirror decoder applies
//  every encoder-stream insert eagerly (evicting blindly, as a real peer does) but decodes field sections
//  *late* and *interleaved across streams*. If the encoder ever emitted an insert that evicted an entry a
//  not-yet-decoded section still referenced, that delayed decode would fail — so a passing run is proof
//  the encoder never evicts a live reference. Insert Count Increment, Section Acknowledgment, and Stream
//  Cancellation are driven back into the encoder so its reference tracking is exercised end to end.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 §2.1.3 — QPACK dynamic encoder eviction-safety fuzz")
struct QPACKEncoderFuzzTests {
    /// A small, deterministic xorshift generator so each seed is a reproducible run.
    private struct SeededGenerator: RandomNumberGenerator {
        var state: UInt64

        init(seed: UInt64) { state = seed == 0 ? 0x9E37_79B9_7F4A_7C15 : seed }

        mutating func next() -> UInt64 {
            state ^= state << 13
            state ^= state >> 7
            state ^= state << 17
            return state
        }
    }

    private struct PendingSection {
        let bytes: [UInt8]
        let expected: [HeaderField]
        let requiredInsertCount0: Bool
    }

    @Test(
        "random encode / increment / acknowledge / cancel sequences always decode (eviction safety)",
        arguments: [1, 2, 3, 5, 8, 13, 21, 34] as [UInt64])
    func evictionSafetyUnderChurn(seed: UInt64) throws {
        var rng = SeededGenerator(seed: seed)
        var encoder = QPACKEncoder()
        encoder.enableDynamicTable(capacity: 256, blockedStreams: 8)  // ~7 entries → constant churn
        var decoder = QPACKDecoder(maxTableCapacity: 256)
        let pool = fieldPool()
        // A per-stream FIFO — a stream decodes its sections in order, but streams interleave.
        var inFlight: [UInt64: [PendingSection]] = [:]
        var ackedInserts = 0

        for _ in 0 ..< 400 {
            let busyStreams = inFlight.filter { !$0.value.isEmpty }.map(\.key)
            let shouldEncode = busyStreams.isEmpty || Int.random(in: 0 ..< 100, using: &rng) < 62
            if shouldEncode {
                try encodeStep(&encoder, &decoder, pool, &inFlight, &ackedInserts, &rng)
            }
            else {
                try deliverStep(&encoder, &decoder, busyStreams, &inFlight, &rng)
            }
        }
        // Drain everything still in flight — each must still decode against the final table.
        for (_, sections) in inFlight {
            for section in sections {
                #expect(try decode(decoder, section.bytes) == section.expected)
            }
        }
    }

    /// Encodes a random section on a random stream, applies its inserts to the mirror, and (sometimes)
    /// feeds an Insert Count Increment back to the encoder.
    private func encodeStep(
        _ encoder: inout QPACKEncoder,
        _ decoder: inout QPACKDecoder,
        _ pool: [HeaderField],
        _ inFlight: inout [UInt64: [PendingSection]],
        _ ackedInserts: inout Int,
        _ rng: inout SeededGenerator
    ) throws {
        let stream = UInt64(Int.random(in: 0 ..< 12, using: &rng) * 4)
        let fields = randomFields(pool, &rng)
        let (section, encoderStream) = encoder.encodeSection(fields, streamID: stream)
        if !encoderStream.isEmpty {
            try applyEncoderStream(&decoder, encoderStream)
        }
        let pending = PendingSection(
            bytes: section,
            expected: fields,
            requiredInsertCount0: section.first == 0x00
        )
        inFlight[stream, default: []].append(pending)
        if decoder.insertCount > ackedInserts, Bool.random(using: &rng) {
            let increment = decoder.insertCount - ackedInserts
            try applyDecoderStream(&encoder, QPACKInstructions.insertCountIncrement(increment))
            ackedInserts = decoder.insertCount
        }
    }

    /// Delivers the oldest in-flight section of a random busy stream — decoding it against the mirror's
    /// current (possibly much-evicted) table — then acknowledges or cancels the stream.
    private func deliverStep(
        _ encoder: inout QPACKEncoder,
        _ decoder: inout QPACKDecoder,
        _ busyStreams: [UInt64],
        _ inFlight: inout [UInt64: [PendingSection]],
        _ rng: inout SeededGenerator
    ) throws {
        let stream = busyStreams[Int.random(in: 0 ..< busyStreams.count, using: &rng)]
        if Int.random(in: 0 ..< 100, using: &rng) < 12 {
            inFlight[stream] = nil  // the peer reset the stream — drop its sections
            try applyDecoderStream(&encoder, streamCancellation(stream))
            return
        }
        guard var sections = inFlight[stream] else {
            return
        }
        let section = sections.removeFirst()
        inFlight[stream] = sections.isEmpty ? nil : sections
        #expect(try decode(decoder, section.bytes) == section.expected)
        if !section.requiredInsertCount0 {  // only a non-zero-RIC section is acknowledged (§4.4.1)
            let ack = QPACKInstructions.sectionAcknowledgment(streamID: stream)
            try applyDecoderStream(&encoder, ack)
        }
    }

    // MARK: Inputs

    private func fieldPool() -> [HeaderField] {
        var pool: [HeaderField] = [
            HeaderField(name: ":status", value: "200"),  // static-exact — never inserted
            HeaderField(name: "content-type", value: "application/json")  // static-exact
        ]
        for name in 0 ..< 6 {
            for value in 0 ..< 3 {
                pool.append(HeaderField(name: "x-h\(name)", value: "v\(name)-\(value)"))
            }
        }
        return pool
    }

    private func randomFields(
        _ pool: [HeaderField], _ rng: inout SeededGenerator
    ) -> [HeaderField] {
        let count = Int.random(in: 1 ... 4, using: &rng)
        var fields: [HeaderField] = []
        for _ in 0 ..< count {
            fields.append(pool[Int.random(in: 0 ..< pool.count, using: &rng)])
        }
        return fields
    }

    private func streamCancellation(_ streamID: UInt64) -> [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(Int(streamID), prefixBits: 6, firstByte: 0x40, into: &out)  // 01 prefix
        return out
    }

    // MARK: Mirror plumbing

    private func applyEncoderStream(_ decoder: inout QPACKDecoder, _ bytes: [UInt8]) throws {
        let result: Result<(consumed: Int, inserts: Int), QPACKError> = bytes.withUnsafeBytes {
            raw in
            Result { () throws(QPACKError) in try decoder.applyEncoderInstructions(raw.bytes) }
        }
        _ = try result.get()
    }

    private func applyDecoderStream(_ encoder: inout QPACKEncoder, _ bytes: [UInt8]) throws {
        let result: Result<Int, QPACKError> = bytes.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in try encoder.applyDecoderInstructions(raw.bytes) }
        }
        _ = try result.get()
    }

    private func decode(_ decoder: QPACKDecoder, _ bytes: [UInt8]) throws -> [HeaderField] {
        let result: Result<[HeaderField], QPACKError> = bytes.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in try decoder.decode(raw.bytes) }
        }
        return try result.get()
    }
}
