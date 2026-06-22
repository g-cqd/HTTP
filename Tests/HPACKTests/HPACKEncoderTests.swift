//
//  HPACKEncoderTests.swift
//  HPACKTests
//
//  RED→GREEN driver for the RFC 7541 §6 encoder: exact static indexing produces the documented single
//  octet, and a stateful encoder round-trips through the (separately RFC-validated) decoder while the
//  two dynamic tables evolve identically — reproducing the Appendix C.3 table sizes.
//

import HTTPCore
import Testing

@testable import HPACK

@Suite("RFC 7541 §6 — HPACK encoder")
struct HPACKEncoderTests {

    private let request1 = [
        HPACKField(name: ":method", value: "GET"), HPACKField(name: ":scheme", value: "http"),
        HPACKField(name: ":path", value: "/"),
        HPACKField(name: ":authority", value: "www.example.com"),
    ]
    private let request2 = [
        HPACKField(name: ":method", value: "GET"), HPACKField(name: ":scheme", value: "http"),
        HPACKField(name: ":path", value: "/"),
        HPACKField(name: ":authority", value: "www.example.com"),
        HPACKField(name: "cache-control", value: "no-cache"),
    ]
    private let request3 = [
        HPACKField(name: ":method", value: "GET"), HPACKField(name: ":scheme", value: "https"),
        HPACKField(name: ":path", value: "/index.html"),
        HPACKField(name: ":authority", value: "www.example.com"),
        HPACKField(name: "custom-key", value: "custom-value"),
    ]

    private func roundTrip(
        _ encoder: inout HPACKEncoder,
        _ decoder: inout HPACKDecoder,
        _ fields: [HPACKField]
    ) throws -> [HPACKField] {
        let block = encoder.encode(fields)
        return try block.withUnsafeBytes { try decoder.decode($0.bytes) }
    }

    // MARK: Representation choices

    @Test(
        "encodes an exact static match as a one-byte indexed field (§6.1)",
        arguments: [
            (HPACKField(name: ":method", value: "GET"), UInt8(0x82)),
            (HPACKField(name: ":path", value: "/index.html"), UInt8(0x85)),
            (HPACKField(name: ":scheme", value: "https"), UInt8(0x87)),
            (HPACKField(name: ":status", value: "200"), UInt8(0x88)),
        ])
    func indexedStaticExact(field: HPACKField, expected: UInt8) {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4096)
        #expect(encoder.encode([field]) == [expected])
    }

    @Test("reuses a static name reference and inserts the field (§6.2.1)")
    func literalWithNameReference() {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4096)
        let block = encoder.encode([HPACKField(name: ":authority", value: "www.example.com")])
        #expect(block.first == 0x41)  // 0x40 | static name index 1 for ":authority"
        #expect(encoder.dynamicTable.size == 57)  // the field was inserted
    }

    // MARK: Round-trip against the conformant decoder

    @Test(
        "round-trips field lists through encode then decode",
        arguments: [
            [HPACKField(name: ":method", value: "GET")],
            [HPACKField(name: "custom-key", value: "custom-value")],
            [HPACKField(name: "x-empty", value: "")],
            [
                HPACKField(name: "accept", value: "text/html"),
                HPACKField(name: "user-agent", value: "swift-http/1.0 (🌍)"),
            ],
        ])
    func roundTrips(fields: [HPACKField]) throws {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4096)
        var decoder = HPACKDecoder(maxDynamicTableSize: 4096)
        #expect(try roundTrip(&encoder, &decoder, fields) == fields)
    }

    @Test("an empty field list encodes and decodes to nothing")
    func emptyRoundTrip() throws {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4096)
        var decoder = HPACKDecoder(maxDynamicTableSize: 4096)
        #expect(try roundTrip(&encoder, &decoder, []).isEmpty)
    }

    @Test("encoder and decoder dynamic tables stay in lock-step across a stream (C.3 sizes)")
    func statefulSequenceStaysSynchronized() throws {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4096)
        var decoder = HPACKDecoder(maxDynamicTableSize: 4096)

        #expect(try roundTrip(&encoder, &decoder, request1) == request1)
        #expect(encoder.dynamicTable.size == 57)
        #expect(decoder.dynamicTable.size == 57)

        #expect(try roundTrip(&encoder, &decoder, request2) == request2)
        #expect(encoder.dynamicTable.size == 110)
        #expect(decoder.dynamicTable.size == 110)

        #expect(try roundTrip(&encoder, &decoder, request3) == request3)
        #expect(encoder.dynamicTable.size == 164)
        #expect(decoder.dynamicTable.size == 164)
    }
}
