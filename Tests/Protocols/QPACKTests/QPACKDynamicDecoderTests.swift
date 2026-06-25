//
//  QPACKDynamicDecoderTests.swift
//  QPACKTests
//
//  RFC 9204 §4.3 / §4.5 — the decoder's dynamic-table path: applying the peer encoder's instruction
//  stream (Set Capacity, Insert With Name Reference, Insert With Literal Name, Duplicate) into the
//  dynamic table, then decoding field sections that reference it through the §4.5.1 Required Insert
//  Count / Base prefix and the §4.5.2–§4.5.5 dynamic representations (indexed, name reference, post-base).
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 §4.3/§4.5 — QPACK dynamic-table decoding")
struct QPACKDynamicDecoderTests {
    private func makeDecoder(capacity: Int = 4_096) -> QPACKDecoder {
        QPACKDecoder(maxTableCapacity: capacity)
    }

    /// Applies encoder-stream instructions, returning the new-insert count.
    @discardableResult
    private func apply(_ decoder: inout QPACKDecoder, _ bytes: [UInt8]) throws -> Int {
        let result: Result<(consumed: Int, inserts: Int), QPACKError> = bytes.withUnsafeBytes {
            raw in
            Result { () throws(QPACKError) in try decoder.applyEncoderInstructions(raw.bytes) }
        }
        return try result.get().inserts
    }

    private func decodeSection(_ decoder: QPACKDecoder, _ bytes: [UInt8]) throws -> [HeaderField] {
        let result: Result<[HeaderField], QPACKError> = bytes.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in try decoder.decode(raw.bytes) }
        }
        return try result.get()
    }

    private func thrownDecoding(_ decoder: QPACKDecoder, _ bytes: [UInt8]) -> QPACKError? {
        let result: Result<[HeaderField], QPACKError> = bytes.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in try decoder.decode(raw.bytes) }
        }
        if case .failure(let error) = result {
            return error
        }
        return nil
    }

    // MARK: Round-trips

    @Test("a dynamic indexed field line resolves the inserted entry (§4.5.2 / §4.3.3)")
    func dynamicIndexedRoundTrip() throws {
        var decoder = makeDecoder()
        try apply(&decoder, insertLiteral("custom", "value"))
        #expect(decoder.insertCount == 1)
        let fields = try decodeSection(
            decoder, section(ric: 1, base: 1, dynamicIndexed(relativeIndex: 0))
        )
        #expect(fields == [HeaderField(name: "custom", value: "value")])
    }

    @Test(
        "insert with a static name reference, then reference it with a new value (§4.3.2 / §4.5.4)")
    func nameReferenceRoundTrip() throws {
        var decoder = makeDecoder()
        // Static entry 0 is `:authority`; the insert copies its name with the value "example.com".
        try apply(&decoder, insertNameReference(staticIndex: 0, "example.com"))
        let fields = try decodeSection(
            decoder, section(ric: 1, base: 1, dynamicNameReference(relativeIndex: 0, "other.com"))
        )
        #expect(fields == [HeaderField(name: ":authority", value: "other.com")])
    }

    @Test("post-base indexing resolves an entry inserted after the Base (§4.5.3 / §3.2.6)")
    func postBaseRoundTrip() throws {
        var decoder = makeDecoder()
        try apply(&decoder, insertLiteral("a", "1") + insertLiteral("b", "2"))  // absolute 0, 1
        // Base 1, post-base 0 → absolute 1 = "b: 2"; RIC 2 since it depends on both inserts.
        let fields = try decodeSection(decoder, section(ric: 2, base: 1, postBaseIndexed(0)))
        #expect(fields == [HeaderField(name: "b", value: "2")])
    }

    @Test("Set Capacity then over-capacity inserts evict the oldest entry (§4.3.1 / §3.2.2)")
    func setCapacityEvicts() throws {
        var decoder = makeDecoder()
        try apply(&decoder, setCapacity(99))  // each 1-char entry sizes 34 → at most two fit
        let inserts = insertLiteral("a", "1") + insertLiteral("b", "2") + insertLiteral("c", "3")
        try apply(&decoder, inserts)
        #expect(decoder.insertCount == 3)  // "a" (absolute 0) evicted; "b","c" remain
        let newest = try decodeSection(
            decoder, section(ric: 3, base: 3, dynamicIndexed(relativeIndex: 0))
        )
        #expect(newest == [HeaderField(name: "c", value: "3")])
    }

    @Test("Duplicate copies an entry to the insert point (§4.3.4)")
    func duplicateRoundTrip() throws {
        var decoder = makeDecoder()
        try apply(&decoder, insertLiteral("dup", "v"))  // absolute 0
        try apply(&decoder, duplicate(0))  // → absolute 1
        #expect(decoder.insertCount == 2)
        let fields = try decodeSection(
            decoder, section(ric: 2, base: 2, dynamicIndexed(relativeIndex: 0))
        )
        #expect(fields == [HeaderField(name: "dup", value: "v")])
    }

    // MARK: Faults

    @Test("a Required Insert Count past the entries received is rejected (§4.5.1 — would block)")
    func requiredInsertCountBeyondInsertsRejected() throws {
        var decoder = makeDecoder()
        try apply(&decoder, insertLiteral("a", "1"))  // insertCount 1
        let bytes = section(ric: 2, base: 2, dynamicIndexed(relativeIndex: 0))  // RIC 2 > 1
        #expect(thrownDecoding(decoder, bytes)?.code == .decompressionFailed)
    }

    @Test("an out-of-range dynamic index is a decompression failure (§4.5.2)")
    func dynamicIndexOutOfRangeRejected() throws {
        var decoder = makeDecoder()
        try apply(&decoder, insertLiteral("a", "1"))
        // relative index 5 against Base 1 → absolute −5, no such entry.
        let bytes = section(ric: 1, base: 1, dynamicIndexed(relativeIndex: 5))
        #expect(thrownDecoding(decoder, bytes)?.code == .decompressionFailed)
    }

    @Test("an oversized Set Capacity is a QPACK_ENCODER_STREAM_ERROR (§4.3.1)")
    func oversizedSetCapacityRejected() {
        var decoder = makeDecoder(capacity: 100)
        let result: Result<(Int, Int), QPACKError> = setCapacity(200)
            .withUnsafeBytes { raw in
                Result { () throws(QPACKError) in
                    let applied = try decoder.applyEncoderInstructions(raw.bytes)
                    return (applied.consumed, applied.inserts)
                }
            }
        if case .failure(let error) = result {
            #expect(error.code == .encoderStreamError)
        }
        else {
            Issue.record("expected an encoder-stream error")
        }
    }

    @Test("a truncated trailing instruction is left unconsumed (incremental, §4.3)")
    func truncatedInstructionLeftUnconsumed() throws {
        var decoder = makeDecoder()
        var bytes = insertLiteral("complete", "entry")
        let completeLength = bytes.count
        bytes += insertLiteral("partial", "value")
        bytes.removeLast(3)  // chop the tail of the second insert's value
        let consumed: Int = try bytes.withUnsafeBytes { raw in
            let result: Result<(consumed: Int, inserts: Int), QPACKError> = Result {
                () throws(QPACKError) in try decoder.applyEncoderInstructions(raw.bytes)
            }
            return try result.get().consumed
        }
        #expect(consumed == completeLength)  // only the first, complete instruction was applied
        #expect(decoder.insertCount == 1)
    }

    // MARK: Encoder-stream instruction builders (RFC 9204 §4.3)

    private func insertLiteral(_ name: String, _ value: String) -> [UInt8] {
        var out: [UInt8] = []
        QPACKString.encode(Array(name.utf8), prefixBits: 5, firstByte: 0x40, into: &out)  // 01
        QPACKString.encode(Array(value.utf8), prefixBits: 7, into: &out)
        return out
    }

    private func insertNameReference(staticIndex: Int, _ value: String) -> [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(staticIndex, prefixBits: 6, firstByte: 0xC0, into: &out)  // 1 T=1
        QPACKString.encode(Array(value.utf8), prefixBits: 7, into: &out)
        return out
    }

    private func setCapacity(_ capacity: Int) -> [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(capacity, prefixBits: 5, firstByte: 0x20, into: &out)  // 001
        return out
    }

    private func duplicate(_ relativeIndex: Int) -> [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(relativeIndex, prefixBits: 5, firstByte: 0x00, into: &out)  // 000
        return out
    }

    // MARK: Field-section builders (RFC 9204 §4.5)

    /// A field section prefix (§4.5.1) for `ric`/`base` followed by `representations` (§4.5.1.2: S=0 with
    /// DeltaBase = Base−RIC when Base ≥ RIC, else S=1 with DeltaBase = RIC−Base−1 for post-base Bases).
    private func section(ric: Int, base: Int, _ representations: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        let encodedInsertCount = ric == 0 ? 0 : (ric % 256) + 1  // FullRange 256 at capacity 4096
        QPACKInteger.encode(encodedInsertCount, prefixBits: 8, into: &out)
        if base >= ric {
            QPACKInteger.encode(base - ric, prefixBits: 7, firstByte: 0x00, into: &out)  // S=0
        }
        else {
            QPACKInteger.encode(ric - base - 1, prefixBits: 7, firstByte: 0x80, into: &out)  // S=1
        }
        out += representations
        return out
    }

    private func dynamicIndexed(relativeIndex: Int) -> [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(relativeIndex, prefixBits: 6, firstByte: 0x80, into: &out)  // 1 T=0
        return out
    }

    private func dynamicNameReference(relativeIndex: Int, _ value: String) -> [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(relativeIndex, prefixBits: 4, firstByte: 0x40, into: &out)  // 01 dyn
        QPACKString.encode(Array(value.utf8), prefixBits: 7, into: &out)
        return out
    }

    private func postBaseIndexed(_ postBaseIndex: Int) -> [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(postBaseIndex, prefixBits: 4, firstByte: 0x10, into: &out)  // 0001
        return out
    }
}
