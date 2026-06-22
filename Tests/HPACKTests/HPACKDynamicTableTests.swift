//
//  HPACKDynamicTableTests.swift
//  HPACKTests
//
//  RED→GREEN driver for the RFC 7541 §4 dynamic table: size accounting (§4.1), the combined index
//  address space (§2.3.3), FIFO eviction (§4.4), size updates (§6.3), and the empty-on-oversize rule.
//

import Testing

@testable import HPACK

@Suite("RFC 7541 §4 — dynamic table")
struct HPACKDynamicTableTests {

    @Test("insertion accounts size and addresses newest-first from index 62 (C.3.2)")
    func insertionAndIndexing() {
        var table = HPACKDynamicTable(maxSize: 4096)
        table.add(HPACKField(name: ":authority", value: "www.example.com"))  // size 57
        table.add(HPACKField(name: "cache-control", value: "no-cache"))  // size 53

        #expect(table.count == 2)
        #expect(table.size == 110)  // RFC 7541 C.3.2 table size
        // Newest first: index 62 is cache-control, 63 is :authority.
        #expect(table.field(at: 62) == HPACKField(name: "cache-control", value: "no-cache"))
        #expect(table.field(at: 63) == HPACKField(name: ":authority", value: "www.example.com"))
    }

    @Test("the combined index space falls through to the static table")
    func combinedIndexSpace() {
        var table = HPACKDynamicTable(maxSize: 4096)
        table.add(HPACKField(name: "cache-control", value: "no-cache"))
        // Index 2 resolves in the static table, 62 in the dynamic table, 64 is past the end.
        #expect(table.field(at: 2) == HPACKField(name: ":method", value: "GET"))
        #expect(table.field(at: 62) == HPACKField(name: "cache-control", value: "no-cache"))
        #expect(table.field(at: 64) == nil)
    }

    @Test("adding beyond the bound evicts the oldest entries (FIFO, §4.4)")
    func evictsOldest() {
        // Each entry is 10 + 15 + 32 = 57 octets; the cap of 120 holds two, so a third evicts.
        var table = HPACKDynamicTable(maxSize: 120)
        table.add(HPACKField(name: ":authority", value: "aaaaaaaaaaaaaaa"))
        table.add(HPACKField(name: ":authority", value: "bbbbbbbbbbbbbbb"))
        table.add(HPACKField(name: ":authority", value: "ccccccccccccccc"))

        #expect(table.count == 2)
        #expect(table.size == 114)
        #expect(table.field(at: 62) == HPACKField(name: ":authority", value: "ccccccccccccccc"))
        #expect(table.field(at: 63) == HPACKField(name: ":authority", value: "bbbbbbbbbbbbbbb"))
        #expect(table.field(at: 64) == nil)  // the first entry was evicted
    }

    @Test("shrinking the maximum size evicts to fit (§6.3)")
    func sizeUpdateEvicts() {
        var table = HPACKDynamicTable(maxSize: 4096)
        table.add(HPACKField(name: ":authority", value: "www.example.com"))  // 57
        table.add(HPACKField(name: "cache-control", value: "no-cache"))  // 53, total 110

        table.setMaxSize(60)  // only the newest 53-octet entry fits
        #expect(table.count == 1)
        #expect(table.size == 53)
        #expect(table.field(at: 62) == HPACKField(name: "cache-control", value: "no-cache"))
    }

    @Test("clearing the size to zero empties the table")
    func sizeUpdateToZero() {
        var table = HPACKDynamicTable(maxSize: 4096)
        table.add(HPACKField(name: "cache-control", value: "no-cache"))
        table.setMaxSize(0)
        #expect(table.count == 0)
        #expect(table.size == 0)
    }

    @Test("an entry larger than the whole table empties it and is not inserted (§4.4)")
    func oversizedEntryEmptiesTable() {
        var table = HPACKDynamicTable(maxSize: 100)
        table.add(HPACKField(name: "cache-control", value: "no-cache"))  // 53, fits
        // 1 + 100 + 32 = 133 octets, larger than the whole 100-octet table.
        table.add(HPACKField(name: "x", value: String(repeating: "y", count: 100)))

        #expect(table.count == 0)
        #expect(table.size == 0)
    }
}
