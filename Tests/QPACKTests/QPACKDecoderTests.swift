//
//  QPACKDecoderTests.swift
//  QPACKTests
//
//  RED→GREEN driver for the RFC 9204 §4.5 field-section decoder with the dynamic table disabled
//  (capacity 0): the §4.5.1 prefix (RIC/Base must be 0), the static-table representations (§4.5.2,
//  §4.5.4, §4.5.6), the RFC 9204 Appendix B.1 worked vector, and the malformations that every fail
//  closed with QPACK_DECOMPRESSION_FAILED — the conformance rows this decoder must satisfy.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 §4.5 — QPACK field-section decoder (static-only, capacity 0)")
struct QPACKDecoderTests {

    private func decode(_ bytes: [UInt8]) throws -> [HeaderField] {
        let result: Result<[HeaderField], QPACKError> = bytes.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in try QPACKDecoder().decode(raw.bytes) }
        }
        return try result.get()
    }

    @Test("RFC 9204 Appendix B.1 — literal field line with a static name reference")
    func appendixB1() throws {
        // 00 00  RIC=0, Base=0 · 51  literal w/ name ref, T=1, name index 1 (:path) · 0b "/index.html"
        let bytes: [UInt8] = [0x00, 0x00, 0x51, 0x0B] + Array("/index.html".utf8)
        #expect(try decode(bytes) == [HeaderField(name: ":path", value: "/index.html")])
    }

    @Test("an indexed static field line resolves to its static entry (§4.5.2)")
    func indexedStatic() throws {
        #expect(try decode([0x00, 0x00, 0xC1]) == [HeaderField(name: ":path", value: "/")])
    }

    @Test("a literal field line with a literal name decodes both strings (§4.5.6)")
    func literalName() throws {
        var block: [UInt8] = [0x00, 0x00]
        QPACKString.encode(Array("custom-key".utf8), prefixBits: 3, firstByte: 0x20, into: &block)
        QPACKString.encode(Array("custom-value".utf8), prefixBits: 7, firstByte: 0, into: &block)
        #expect(try decode(block) == [HeaderField(name: "custom-key", value: "custom-value")])
    }

    @Test("a literal field line with a static name reference + literal value (§4.5.4)")
    func literalWithNameReference() throws {
        // 50 = literal w/ name ref, T=1, name index 0 (:authority); value "www.example.com".
        var block: [UInt8] = [0x00, 0x00, 0x50]
        QPACKString.encode(Array("www.example.com".utf8), prefixBits: 7, firstByte: 0, into: &block)
        #expect(try decode(block) == [HeaderField(name: ":authority", value: "www.example.com")])
    }

    @Test("consecutive representations decode in order")
    func multiple() throws {
        let bytes: [UInt8] = [0x00, 0x00, 0xC1, 0xC0 | 17, 0xC0 | 23]
        #expect(
            try decode(bytes) == [
                HeaderField(name: ":path", value: "/"),
                HeaderField(name: ":method", value: "GET"),
                HeaderField(name: ":scheme", value: "https"),
            ])
    }

    @Test("an empty (prefix-only) field section decodes to no fields")
    func prefixOnly() throws {
        #expect(try decode([0x00, 0x00]).isEmpty)
    }

    @Test(
        "malformed field sections fail closed with QPACK_DECOMPRESSION_FAILED (RFC 9204 §6)",
        arguments: [
            (label: "empty block (missing prefix)", bytes: [] as [UInt8]),
            // §2.1.1 — RIC beyond the (zero) blocked-streams limit. First octet = RIC = 5.
            (label: "non-zero Required Insert Count", bytes: [0x05, 0x00]),
            // §4.5.1 — non-zero Base references absent dynamic entries. Base = 2.
            (label: "non-zero Base", bytes: [0x00, 0x02]),
            // §4.5.2 — indexed reference into the static table past the end (index 99).
            (label: "invalid static index", bytes: [0x00, 0x00, 0xFF, 0x24]),
            // §3.2.2 — indexed dynamic reference (T=0) with the table disabled.
            (label: "dynamic indexed reference", bytes: [0x00, 0x00, 0x80]),
            // §4.5.3 — post-base indexed representation (0001) needs the dynamic table.
            (label: "post-base indexed", bytes: [0x00, 0x00, 0x10]),
            // §4.5.5 — post-base name reference (0000) needs the dynamic table.
            (label: "post-base name reference", bytes: [0x00, 0x00, 0x00]),
            // §4.5.4 — value string truncated below its declared length.
            (label: "truncated value string", bytes: [0x00, 0x00, 0x51, 0x0B, 0x2F, 0x69, 0x6E]),
        ] as [(label: String, bytes: [UInt8])])
    func malformed(_ testCase: (label: String, bytes: [UInt8])) {
        #expect("\(testCase.label) is a decompression failure") {
            _ = try decode(testCase.bytes)
        } throws: { error in
            (error as? QPACKError)?.code == .decompressionFailed
        }
    }
}
