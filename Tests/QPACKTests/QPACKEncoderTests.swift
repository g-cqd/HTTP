//
//  QPACKEncoderTests.swift
//  QPACKTests
//
//  RED→GREEN driver for the RFC 9204 §4.5 static-only encoder: the §4.5.1 prefix, the three static
//  representations (indexed, static name reference, literal name), and the round-trip property that an
//  encoded field section decodes back to the same fields with this module's decoder.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 §4.5 — QPACK field-section encoder (static-only)")
struct QPACKEncoderTests {

    private func roundTrip(_ fields: [HeaderField]) throws -> [HeaderField] {
        let block = QPACKEncoder().encode(fields)
        let result: Result<[HeaderField], QPACKError> = block.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in try QPACKDecoder().decode(raw.bytes) }
        }
        return try result.get()
    }

    @Test("the encoded section opens with the §4.5.1 prefix (RIC=0, Base=0)")
    func prefix() {
        let block = QPACKEncoder().encode([])
        #expect(block == [0x00, 0x00])
    }

    @Test("an exact static match encodes as an indexed field line (§4.5.2)")
    func indexed() {
        // :method GET is static index 17 → 0xC0 | 17.
        let block = QPACKEncoder().encode([HeaderField(name: ":method", value: "GET")])
        #expect(block == [0x00, 0x00, 0xC0 | 17])
    }

    @Test("a static name match encodes as a literal with name reference (§4.5.4)")
    func nameReference() {
        // :authority is name index 0 → 0x50 | 0; value "x" as a 1-octet raw string literal.
        let block = QPACKEncoder().encode([HeaderField(name: ":authority", value: "x")])
        #expect(block == [0x00, 0x00, 0x50, 0x01, UInt8(ascii: "x")])
    }

    @Test(
        "field lists round-trip through encode then decode",
        arguments: [
            [HeaderField(name: ":path", value: "/")],
            [
                HeaderField(name: ":method", value: "GET"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":path", value: "/index.html"),
                HeaderField(name: ":authority", value: "www.example.com"),
            ],
            // A field whose name is unknown forces the literal-name representation (§4.5.6).
            [HeaderField(name: "x-custom-header", value: "custom value with spaces")],
            // A known name with a novel value forces a static name reference (§4.5.4).
            [HeaderField(name: "date", value: "Mon, 21 Oct 2013 20:13:21 GMT")],
        ] as [[HeaderField]])
    func roundTrips(_ fields: [HeaderField]) throws {
        #expect(try roundTrip(fields) == fields)
    }
}
