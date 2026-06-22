//
//  HPACKConformanceTests.swift
//  HPACKTests
//
//  h2spec conformance — the `hpack` group (RFC 7541), driven against the `HPACKDecoder`. h2spec checks
//  that a decoder fails closed on each malformed representation; in HTTP/2 every one of these surfaces
//  as a connection COMPRESSION_ERROR (RFC 9113 §4.3). Each crafted vector is annotated with the bit
//  layout it exploits.
//
//  Huffman faults (§5.2): in the canonical code only EOS is all-ones, so a run of 1-bits never matches
//  a real symbol — it is either valid EOS-prefix padding (≤ 7 bits, all ones) or a fault. That makes
//  the three §5.2 vectors below minimal and auditable.
//

import HTTPCore
import Testing

@testable import HPACK

@Suite("h2spec hpack — malformed HPACK is a decoding error (RFC 7541)")
struct HPACKConformanceTests {

    @Test(
        "hpack — a malformed representation is a decoding error (RFC 7541)",
        arguments: [
            // §2.3.3 — index past the table. 0xBF = indexed field, index 63 (static ends at 61).
            (
                label: "2.3.3/1 indexed field, invalid index", bytes: [0xBF] as [UInt8],
                error: HPACKError.invalidIndex, maxTable: 4096
            ),
            // §2.3.3 — literal with an invalid name index. 0x7E = literal (incr. indexing), name 62.
            (
                label: "2.3.3/2 literal field, invalid index", bytes: [0x7E],
                error: .invalidIndex, maxTable: 4096
            ),
            // §4.2 — a dynamic table size update after a field. 0x82 = indexed :method; 0x20 = update.
            (
                label: "4.2/1 size update at end of block", bytes: [0x82, 0x20],
                error: .invalidTableSizeUpdate, maxTable: 4096
            ),
            // §5.2 — Huffman padding longer than 7 bits. 0x07='0'+3 ones, 0xFF=8 ones → 11 ones.
            (
                label: "5.2/1 Huffman padding longer than 7 bits",
                bytes: [0x00, 0x82, 0x07, 0xFF, 0x00],
                error: .invalidHuffman, maxTable: 4096
            ),
            // §5.2 — Huffman padding not all ones. 0x00 = '0' (00000) + 000 padding (contains zeros).
            (
                label: "5.2/2 Huffman padding by zero", bytes: [0x00, 0x81, 0x00, 0x00],
                error: .invalidHuffman, maxTable: 4096
            ),
            // §5.2 — the EOS symbol in the input. Four 0xFF octets = 32 ones → EOS at 30.
            (
                label: "5.2/3 Huffman EOS symbol",
                bytes: [0x00, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
                error: .invalidHuffman, maxTable: 4096
            ),
            // §6.1 — an indexed field with index 0. 0x80 = indexed, index 0.
            (
                label: "6.1/1 indexed field with index 0", bytes: [0x80],
                error: .invalidIndex, maxTable: 4096
            ),
            // §6.3 — a size update above SETTINGS_HEADER_TABLE_SIZE. 0x3F 0xA9 0x01 = update to 200.
            (
                label: "6.3/1 size update larger than the maximum", bytes: [0x3F, 0xA9, 0x01],
                error: .invalidTableSizeUpdate, maxTable: 100
            ),
        ])
    func malformedHPACKIsDecodingError(
        _ testCase: (label: String, bytes: [UInt8], error: HPACKError, maxTable: Int)
    ) {
        #expect(throws: testCase.error) {
            var decoder = HPACKDecoder(maxDynamicTableSize: testCase.maxTable)
            try testCase.bytes.withUnsafeBytes { try decoder.decode($0.bytes) }
        }
    }

    // h2spec coverage: §2.3.3 (2) + §4.2 (1) + §5.2 (3) + §6.1 (1) + §6.3 (1) = 8 cases.
}
