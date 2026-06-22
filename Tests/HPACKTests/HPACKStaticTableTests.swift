//
//  HPACKStaticTableTests.swift
//  HPACKTests
//
//  RED→GREEN driver for the RFC 7541 Appendix A static table: its boundary entries, the §4.1 entry
//  size, and out-of-range indexing.
//

import HTTPCore
import Testing

@testable import HPACK

@Suite("RFC 7541 Appendix A — static table")
struct HPACKStaticTableTests {

    @Test("has exactly 61 entries")
    func entryCount() {
        #expect(HPACKStaticTable.count == 61)
        #expect(HPACKStaticTable.entries.count == 61)
    }

    @Test(
        "maps the documented indices to their entries",
        arguments: [
            (1, HPACKField(name: ":authority")),
            (2, HPACKField(name: ":method", value: "GET")),
            (4, HPACKField(name: ":path", value: "/")),
            (8, HPACKField(name: ":status", value: "200")),
            (16, HPACKField(name: "accept-encoding", value: "gzip, deflate")),
            (32, HPACKField(name: "cookie")),
            (61, HPACKField(name: "www-authenticate")),
        ])
    func indexedEntries(index: Int, expected: HPACKField) {
        #expect(HPACKStaticTable.field(at: index) == expected)
    }

    @Test("indices outside 1...61 return nil")
    func outOfRange() {
        #expect(HPACKStaticTable.field(at: 0) == nil)
        #expect(HPACKStaticTable.field(at: 62) == nil)
        #expect(HPACKStaticTable.field(at: -1) == nil)
    }

    @Test("entry size is name + value octets + 32 (RFC 7541 §4.1)")
    func entrySize() {
        #expect(HPACKField(name: ":authority").tableSize == 42)  // 10 + 0 + 32
        #expect(HPACKField(name: ":method", value: "GET").tableSize == 42)  // 7 + 3 + 32
        // "custom-key" (10) + "custom-value" (12) + 32 = 54
        #expect(HPACKField(name: "custom-key", value: "custom-value").tableSize == 54)
    }
}
