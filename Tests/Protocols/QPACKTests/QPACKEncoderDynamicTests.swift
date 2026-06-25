//
//  QPACKEncoderDynamicTests.swift
//  QPACKTests
//
//  RFC 9204 §4.3 / §4.5 — the encoder's dynamic-table path, proven end-to-end against the decoder: a
//  section the encoder produces (plus the encoder-stream inserts it emits) must decode back to the
//  original fields. The conservative strategy is exercised directly — a field is inserted only on its
//  second use, referenced only after an Insert Count Increment, and never evicts — so each property is a
//  test: first use stays literal (RIC 0), the recurrence inserts, and acknowledgment unlocks the
//  dynamic reference.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 §4.3/§4.5 — QPACK dynamic-table encoding (end-to-end)")
struct QPACKEncoderDynamicTests {
    /// Encodes a section, applies any encoder-stream inserts to the decoder, and decodes the section.
    private func roundTrip(
        _ encoder: inout QPACKEncoder,
        _ decoder: inout QPACKDecoder,
        _ fields: [HeaderField],
        streamID: UInt64 = 0
    ) throws -> (decoded: [HeaderField], section: [UInt8], encoderStream: [UInt8]) {
        let (section, encoderStream) = encoder.encodeSection(fields, streamID: streamID)
        if !encoderStream.isEmpty {
            try apply(&decoder, encoderStream)
        }
        let decoded = try decodeSection(decoder, section)
        return (decoded, section, encoderStream)
    }

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

    private func makePair(
        capacity: Int = 4_096, blockedStreams: Int = 0
    ) -> (QPACKEncoder, QPACKDecoder) {
        var encoder = QPACKEncoder()
        encoder.enableDynamicTable(capacity: capacity, blockedStreams: blockedStreams)
        return (encoder, QPACKDecoder(maxTableCapacity: capacity))
    }

    @Test("first use stays literal, the recurrence inserts, acknowledgment unlocks the reference")
    func insertOnSecondUseThenReference() throws {
        var (encoder, decoder) = makePair()
        let fields = [HeaderField(name: "x-app", value: "v1")]

        // First sighting → no insert (insert-on-second-use); the encoder stream carries only the one-time
        // Set Capacity, and the section is a self-contained literal.
        let first = try roundTrip(&encoder, &decoder, fields)
        #expect(first.decoded == fields)
        #expect(first.encoderStream == QPACKInstructions.setDynamicTableCapacity(4_096))
        #expect(decoder.insertCount == 0)

        // Recurrence → the encoder inserts it; the section is still literal (not yet known-received).
        let second = try roundTrip(&encoder, &decoder, fields)
        #expect(second.decoded == fields)
        #expect(!second.encoderStream.isEmpty)
        #expect(decoder.insertCount == 1)
        #expect(second.section.first == 0x00)  // Required Insert Count still 0

        // The peer acknowledges the insert → the next section references it dynamically.
        encoder.acknowledgeInserts(1)
        let third = try roundTrip(&encoder, &decoder, fields)
        #expect(third.decoded == fields)
        #expect(third.encoderStream.isEmpty)  // no new insert
        #expect(third.section.first != 0x00)  // a non-zero Required Insert Count prefix
    }

    @Test("a never-acknowledged insert is never referenced, yet every section still decodes")
    func neverBlocksWithoutAcknowledgment() throws {
        var (encoder, decoder) = makePair()
        let fields = [HeaderField(name: "x-trace", value: "abc123")]
        // Many repetitions without any acknowledgment: at most one insert, never a dynamic reference.
        for _ in 0 ..< 5 {
            let result = try roundTrip(&encoder, &decoder, fields)
            #expect(result.decoded == fields)
            #expect(result.section.first == 0x00)  // RIC 0 — no reference, so the peer never blocks
        }
        #expect(decoder.insertCount == 1)  // inserted once on the second use, never again
    }

    @Test("a static-table field is never inserted — the static representation already wins")
    func staticFieldNeverInserted() throws {
        var (encoder, decoder) = makePair()
        let fields = [
            HeaderField(name: ":status", value: "200"),  // static-exact
            HeaderField(name: "content-type", value: "application/json"),  // static-exact
            HeaderField(name: "accept-ranges", value: "bytes")  // static-exact
        ]
        for _ in 0 ..< 3 {
            let result = try roundTrip(&encoder, &decoder, fields)
            #expect(result.decoded == fields)
            #expect(result.section.first == 0x00)  // static-only: Required Insert Count 0
        }
        #expect(decoder.insertCount == 0)  // static fields are never inserted
    }

    @Test("a realistic response with mixed static, dynamic, and literal fields round-trips")
    func mixedResponseRoundTrip() throws {
        var (encoder, decoder) = makePair()
        let fields = [
            HeaderField(name: ":status", value: "200"),
            HeaderField(name: "content-type", value: "application/json"),
            HeaderField(name: "x-app-version", value: "2026.6.1")
        ]
        // Prime: the custom field is inserted on its second use and acknowledged.
        _ = try roundTrip(&encoder, &decoder, fields)
        _ = try roundTrip(&encoder, &decoder, fields)
        encoder.acknowledgeInserts(decoder.insertCount)

        let result = try roundTrip(&encoder, &decoder, fields)
        #expect(result.decoded == fields)
        #expect(result.section.first != 0x00)  // the custom field is now a dynamic reference
    }

    @Test("a repeat is referenced immediately when blocking is allowed (§2.1.2)")
    func referencesFreshInsertWhenBlockingAllowed() throws {
        var (encoder, decoder) = makePair(blockedStreams: 4)
        let fields = [HeaderField(name: "x-app", value: "v1")]

        // First use: recorded, not inserted — a literal section.
        let first = try roundTrip(&encoder, &decoder, fields, streamID: 0)
        #expect(first.section.first == 0x00)

        // Second use: inserted AND referenced in the same section, without waiting for an ack.
        let second = try roundTrip(&encoder, &decoder, fields, streamID: 4)
        #expect(second.decoded == fields)
        #expect(!second.encoderStream.isEmpty)  // the insert
        #expect(second.section.first != 0x00)  // a non-zero Required Insert Count — referenced now
        #expect(decoder.insertCount == 1)
    }

    @Test("a referenced entry is not evicted; acknowledging it frees the slot (§2.1.3)")
    func referencedEntryIsNotEvicted() throws {
        // A 40-octet table holds exactly one single-character entry (1 + 1 + 32 = 34 octets).
        var (encoder, decoder) = makePair(capacity: 40, blockedStreams: 4)
        let entryA = [HeaderField(name: "a", value: "1")]
        let entryB = [HeaderField(name: "b", value: "2")]

        // Insert and reference A on stream 0 (its reference is now outstanding, unacknowledged).
        _ = try roundTrip(&encoder, &decoder, entryA, streamID: 0)
        let aReferenced = try roundTrip(&encoder, &decoder, entryA, streamID: 0)
        #expect(aReferenced.section.first != 0x00)
        #expect(decoder.insertCount == 1)

        // B wants in, but inserting it would evict the still-referenced A → B stays literal.
        _ = try roundTrip(&encoder, &decoder, entryB, streamID: 4)
        let bBlocked = try roundTrip(&encoder, &decoder, entryB, streamID: 4)
        #expect(bBlocked.encoderStream.isEmpty)  // no insert — A could not be evicted
        #expect(decoder.insertCount == 1)

        // Acknowledge stream 0 → A is released → B can now evict A and take its place.
        try applyDecoder(&encoder, QPACKInstructions.sectionAcknowledgment(streamID: 0))
        let bInserted = try roundTrip(&encoder, &decoder, entryB, streamID: 4)
        #expect(!bInserted.encoderStream.isEmpty)  // A evicted, B inserted
        #expect(bInserted.decoded == entryB)
        #expect(decoder.insertCount == 2)
    }

    @Test("the blocked-stream limit is respected — a stream past it falls back to literal (§2.1.2)")
    func blockedStreamLimitFallsBackToLiteral() throws {
        var (encoder, decoder) = makePair(blockedStreams: 1)
        let one = [HeaderField(name: "x-a", value: "1")]
        let two = [HeaderField(name: "x-b", value: "2")]

        // Prime each value (first use records it) on its own stream.
        _ = try roundTrip(&encoder, &decoder, one, streamID: 0)
        _ = try roundTrip(&encoder, &decoder, two, streamID: 4)

        // Stream 0 blocks (within the limit of 1); stream 4 would be a second blocked stream → literal.
        let blocked = try roundTrip(&encoder, &decoder, one, streamID: 0)
        let fellBack = try roundTrip(&encoder, &decoder, two, streamID: 4)
        #expect(blocked.section.first != 0x00)  // referenced (blocked)
        #expect(fellBack.section.first == 0x00)  // not referenced — would exceed the limit
        #expect(fellBack.decoded == two)
    }

    // MARK: Helpers

    /// Applies decoder-stream instruction `bytes` to the encoder, returning the octets consumed.
    @discardableResult
    private func applyDecoder(_ encoder: inout QPACKEncoder, _ bytes: [UInt8]) throws -> Int {
        let result: Result<Int, QPACKError> = bytes.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in try encoder.applyDecoderInstructions(raw.bytes) }
        }
        return try result.get()
    }
}
