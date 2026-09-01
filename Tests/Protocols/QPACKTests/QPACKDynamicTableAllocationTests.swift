//
//  QPACKDynamicTableAllocationTests.swift
//  QPACKTests
//
//  Allocation ceilings for the RFC 9204 §3.2 dynamic-table structures. The table backs the HTTP/3
//  encoder's hot path, so a steady-state insert and either encoder lookup must cost no heap traffic at
//  all, and must still cost none as the table grows — hence every measurement runs at two very
//  different capacities. What trips these guards is a per-operation copy, box, CoW clone or ring
//  regrowth: the failure modes that scale heap traffic with request rate.
//
//  Two limits on the oracle, stated so these guards are not read as more than they are. It counts
//  `malloc` calls, so it cannot see a `memmove` (exactly what the superseded newest-first
//  `insert(at: 0)` did per insert) nor a linear scan — so it does NOT by itself establish the O(1)
//  claim, which rests on the hash probe and the single ring write in QPACKDynamicTable.swift, with
//  `qpack/DynamicTable/*` in the benchmark package covering the time. And it charges a phantom
//  allocation per loop iteration in the unoptimized test build, so every measured body here is ONE
//  operation with the warm-up loops outside `mallocDelta`, as in the rest of the repo's alloc tests.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import QPACK

@Suite("QPACK dynamic-table allocation ceilings — the §3.2 insert/lookup structures")
struct QPACKDynamicTableAllocationTests {
    /// The octet size every entry in these tests takes in the table.
    ///
    /// A fixed-width 10-octet name, an empty value, and the §3.2.1 per-entry constant 32. Uniform
    /// sizing makes the live-entry count a clean function of the capacity.
    private static let entrySize = 42

    /// A realistic negotiated capacity (4 KiB, ~97 live entries) and one 16× larger (~1560 entries) —
    /// the pair that turns each guard below into a statement about invariance with table size.
    private static let capacities = [4_096, 65_536]

    /// The entry with the given index, zero-padded so all 4-digit indices size identically.
    private static func entry(_ index: Int) -> HeaderField {
        var digits = String(index)
        while digits.count < 4 {
            digits = "0" + digits
        }
        return HeaderField(name: "field-" + digits, value: "")
    }

    /// A table churned well past its capacity, so the ring sits at its high-water mark and both index
    /// maps at their steady capacity — the state a long-lived HTTP/3 connection's encoder runs in.
    private static func warmedTable(capacity: Int) -> QPACKDynamicTable {
        var table = QPACKDynamicTable(capacity: capacity)
        for index in 0 ..< (capacity / entrySize) * 3 {
            table.insert(entry(index))
        }
        return table
    }

    @Test(
        "a steady-state insert allocates nothing, at any table size (§3.2.2)",
        arguments: capacities
    )
    func steadyStateInsertAllocatesNothing(capacity: Int) {
        var table = Self.warmedTable(capacity: capacity)
        // Past the warm-up an insert only evicts the oldest entry and writes one slot: the ring is at
        // its high-water mark so it never regrows, and both index maps are keyed on the absolute
        // index, which §3.2.4 guarantees eviction never changes — so neither is rewritten.
        expectAllocations(noMoreThan: 0) {
            table.insert(Self.entry(9_001))
        }
        #expect(table.count == capacity / Self.entrySize)
    }

    @Test(
        "the encoder's exact and name lookups allocate nothing, at any table size (§3.2.4/§4.5.4)",
        arguments: capacities
    )
    func encoderLookupsAllocateNothing(capacity: Int) {
        let table = Self.warmedTable(capacity: capacity)
        let hit = Self.entry((capacity / Self.entrySize) * 3 - 1)  // the most recent insert
        // Warm up once so the first probe's lazy work is not charged to the measured run.
        _ = table.absoluteIndex(of: hit)
        _ = table.absoluteIndex(forName: hit.name)

        expectAllocations(noMoreThan: 0) {
            _ = table.absoluteIndex(of: hit)
        }
        expectAllocations(noMoreThan: 0) {
            _ = table.absoluteIndex(forName: hit.name)
        }
        // A miss must be just as cheap — the encoder takes this path for every novel field.
        expectAllocations(noMoreThan: 0) {
            _ = table.absoluteIndex(of: Self.entry(9_002))
        }
        #expect(table.absoluteIndex(of: hit) != nil)
    }

    @Test(
        "the §3.2.4-§3.2.6 index conversions allocate nothing, at any table size",
        arguments: capacities
    )
    func indexConversionsAllocateNothing(capacity: Int) {
        let table = Self.warmedTable(capacity: capacity)
        let base = table.insertCount
        _ = table.field(atAbsolute: base - 1)  // warm up

        expectAllocations(noMoreThan: 0) {
            _ = table.field(atAbsolute: base - 1)
        }
        expectAllocations(noMoreThan: 0) {
            _ = table.field(base: base, relativeIndex: 0)
        }
        expectAllocations(noMoreThan: 0) {
            _ = table.field(relativeToInsertPoint: 0)
        }
        #expect(table.field(atAbsolute: base - 1) != nil)
    }
}
