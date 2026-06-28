//
//  HPACKDecoderTests.swift
//  HPACKTests
//
//  RED→GREEN driver for the RFC 7541 §6 decoder, validated end-to-end against the four Appendix C
//  request/response sequences (the gold-standard conformance vectors) — without Huffman (C.3, C.5)
//  and with it (C.4, C.6), including dynamic-table evolution and eviction — plus the §6 error modes.
//

import HTTPCore
import Testing

@testable import HPACK

@Suite("RFC 7541 §6 — HPACK decoder")
struct HPACKDecoderTests {
    /// Parses a whitespace-grouped hex string (as the RFC prints wire dumps) into octets.
    private func hex(_ string: String) -> [UInt8] {
        let digits = Array(string.filter { !$0.isWhitespace })
        var bytes: [UInt8] = []
        bytes.reserveCapacity(digits.count / 2)
        var index = 0
        while index + 1 < digits.count {
            if let byte = UInt8(String(digits[index ... (index + 1)]), radix: 16) {
                bytes.append(byte)
            }
            index += 2
        }
        return bytes
    }

    private func decode(_ decoder: inout HPACKDecoder, _ block: [UInt8]) throws -> [HPACKField] {
        try block.withUnsafeBytes { try decoder.decode($0.bytes) }
    }

    @Test("a block past maxFieldCount is a decoding error — the header-count bomb (audit HP-F1)")
    func tooManyFieldsIsRejected() {
        // Four indexed `:method GET` references (0x82) against a 3-field cap — each is one octet, so
        // the byte budget never trips; only the count limit catches it (RFC 9113 §8.2.3).
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096, limits: HTTPLimits(maxFieldCount: 3))
        #expect(throws: HPACKError.tooManyFields) {
            _ = try decode(&decoder, [0x82, 0x82, 0x82, 0x82])
        }
    }

    @Test("a block at exactly maxFieldCount still decodes (boundary)")
    func atMaxFieldCountDecodes() throws {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096, limits: HTTPLimits(maxFieldCount: 3))
        #expect(try decode(&decoder, [0x82, 0x82, 0x82]).count == 3)
    }

    // The decoded request/response field lists are identical for the raw and Huffman variants.
    private let request1 = [
        HPACKField(name: ":method", value: "GET"), HPACKField(name: ":scheme", value: "http"),
        HPACKField(name: ":path", value: "/"),
        HPACKField(name: ":authority", value: "www.example.com")
    ]
    private let request2 = [
        HPACKField(name: ":method", value: "GET"), HPACKField(name: ":scheme", value: "http"),
        HPACKField(name: ":path", value: "/"),
        HPACKField(name: ":authority", value: "www.example.com"),
        HPACKField(name: "cache-control", value: "no-cache")
    ]
    private let request3 = [
        HPACKField(name: ":method", value: "GET"), HPACKField(name: ":scheme", value: "https"),
        HPACKField(name: ":path", value: "/index.html"),
        HPACKField(name: ":authority", value: "www.example.com"),
        HPACKField(name: "custom-key", value: "custom-value")
    ]
    private let response1 = [
        HPACKField(name: ":status", value: "302"),
        HPACKField(name: "cache-control", value: "private"),
        HPACKField(name: "date", value: "Mon, 21 Oct 2013 20:13:21 GMT"),
        HPACKField(name: "location", value: "https://www.example.com")
    ]
    private let response2 = [
        HPACKField(name: ":status", value: "307"),
        HPACKField(name: "cache-control", value: "private"),
        HPACKField(name: "date", value: "Mon, 21 Oct 2013 20:13:21 GMT"),
        HPACKField(name: "location", value: "https://www.example.com")
    ]
    private let response3 = [
        HPACKField(name: ":status", value: "200"),
        HPACKField(name: "cache-control", value: "private"),
        HPACKField(name: "date", value: "Mon, 21 Oct 2013 20:13:22 GMT"),
        HPACKField(name: "location", value: "https://www.example.com"),
        HPACKField(name: "content-encoding", value: "gzip"),
        HPACKField(
            name: "set-cookie", value: "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
        )
    ]

    // MARK: C.3 — requests, no Huffman

    @Test("C.3 — three requests without Huffman, dynamic table evolving")
    func requestsWithoutHuffman() throws {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        #expect(
            try decode(&decoder, hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"))
                == request1)
        #expect(decoder.dynamicTable.size == 57)
        #expect(try decode(&decoder, hex("8286 84be 5808 6e6f 2d63 6163 6865")) == request2)
        #expect(decoder.dynamicTable.size == 110)
        #expect(
            try decode(
                &decoder,
                hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65")
            )
                == request3
        )
        #expect(decoder.dynamicTable.size == 164)
    }

    // MARK: C.4 — requests, Huffman

    @Test("C.4 — three requests with Huffman, dynamic table evolving")
    func requestsWithHuffman() throws {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        #expect(try decode(&decoder, hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff")) == request1)
        #expect(decoder.dynamicTable.size == 57)
        #expect(try decode(&decoder, hex("8286 84be 5886 a8eb 1064 9cbf")) == request2)
        #expect(decoder.dynamicTable.size == 110)
        #expect(
            try decode(&decoder, hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"))
                == request3)
        #expect(decoder.dynamicTable.size == 164)
    }

    // MARK: C.5 — responses, no Huffman, table capped at 256 (forces eviction)

    @Test("C.5 — three responses without Huffman, with eviction")
    func responsesWithoutHuffman() throws {
        var decoder = HPACKDecoder(maxDynamicTableSize: 256)
        #expect(
            try decode(
                &decoder,
                hex(
                    "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 "
                        + "2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 "
                        + "6c65 2e63 6f6d"
                )
            ) == response1
        )
        #expect(decoder.dynamicTable.size == 222)
        #expect(try decode(&decoder, hex("4803 3330 37c1 c0bf")) == response2)
        #expect(decoder.dynamicTable.size == 222)
        #expect(
            try decode(
                &decoder,
                hex(
                    "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d "
                        + "54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 "
                        + "5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e "
                        + "3d31"
                )
            ) == response3
        )
        #expect(decoder.dynamicTable.size == 215)
    }

    // MARK: C.6 — responses, Huffman, table capped at 256

    @Test("C.6 — three responses with Huffman, with eviction")
    func responsesWithHuffman() throws {
        var decoder = HPACKDecoder(maxDynamicTableSize: 256)
        #expect(
            try decode(
                &decoder,
                hex(
                    "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 "
                        + "2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3"
                )
            ) == response1
        )
        #expect(decoder.dynamicTable.size == 222)
        #expect(try decode(&decoder, hex("4883 640e ffc1 c0bf")) == response2)
        #expect(decoder.dynamicTable.size == 222)
        #expect(
            try decode(
                &decoder,
                hex(
                    "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab "
                        + "77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f "
                        + "9587 3160 65c0 03ed 4ee5 b106 3d50 07"
                )
            ) == response3
        )
        #expect(decoder.dynamicTable.size == 215)
    }

    // MARK: §6 error modes

    @Test("an indexed field with index 0 is a decoding error (§6.1)")
    func indexZeroIsInvalid() {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        #expect(throws: HPACKError.invalidIndex) { try decode(&decoder, [0x80]) }
    }

    @Test("an index past the table is a decoding error (§2.3.3)")
    func indexOutOfRangeIsInvalid() {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        // 0xBF is an indexed field at index 63 — past the static table, with the dynamic table empty.
        #expect(throws: HPACKError.invalidIndex) { try decode(&decoder, [0xBF]) }
    }

    @Test("a size update above the negotiated maximum is rejected (§6.3)")
    func oversizedSizeUpdateIsInvalid() {
        var decoder = HPACKDecoder(maxDynamicTableSize: 100)
        // 0x3F 0xA9 0x01 = dynamic table size update to 200 > 100.
        #expect(throws: HPACKError.invalidTableSizeUpdate) {
            try decode(&decoder, [0x3F, 0xA9, 0x01])
        }
    }

    @Test("a valid size update shrinks the dynamic table (§6.3)")
    func validSizeUpdate() throws {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        #expect(try decode(&decoder, [0x20]).isEmpty)  // 0x20 = size update to 0
        #expect(decoder.dynamicTable.maxSize == 0)
    }

    @Test("at most two consecutive size updates are accepted; a third is rejected (§4.2)")
    func boundsSizeUpdateRun() throws {
        var ok = HPACKDecoder(maxDynamicTableSize: 4_096)
        #expect(try decode(&ok, [0x20, 0x20]).isEmpty)  // two updates before any field are allowed
        var flood = HPACKDecoder(maxDynamicTableSize: 4_096)
        #expect(throws: HPACKError.invalidTableSizeUpdate) {
            try decode(&flood, [0x20, 0x20, 0x20])  // a third is an eviction-churn vector
        }
    }
}
