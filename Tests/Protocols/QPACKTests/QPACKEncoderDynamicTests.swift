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
        _ encoder: inout QPACKEncoder, _ decoder: inout QPACKDecoder, _ fields: [HeaderField]
    ) throws -> (decoded: [HeaderField], section: [UInt8], encoderStream: [UInt8]) {
        let (section, encoderStream) = encoder.encodeSection(fields)
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

    private func makePair() -> (QPACKEncoder, QPACKDecoder) {
        var encoder = QPACKEncoder()
        encoder.enableDynamicTable(capacity: 4_096)
        return (encoder, QPACKDecoder(maxTableCapacity: 4_096))
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
}
