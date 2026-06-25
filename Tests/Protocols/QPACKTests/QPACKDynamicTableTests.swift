//
//  QPACKDynamicTableTests.swift
//  QPACKTests
//
//  RFC 9204 §3.2 — the QPACK dynamic table. These tests pin the absolute-index / Base-relative /
//  post-base / insert-point arithmetic (§3.2.4–§3.2.6) that is the known QPACK interop trap, plus the
//  §3.2.2 eviction and capacity behavior. The table is a separate index space from the static table, so
//  these lookups never touch the 99-entry static table.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 §3.2 — QPACK dynamic table")
struct QPACKDynamicTableTests {
    private func field(_ name: String, _ value: String = "") -> HeaderField {
        HeaderField(name: name, value: value)
    }

    // MARK: Absolute indexing (§3.2.4)

    @Test("the first insert gets absolute index 0 and the index increments per insert (§3.2.4)")
    func absoluteIndexingIncrements() {
        var table = QPACKDynamicTable(capacity: 4_096)
        #expect(table.insertCount == 0)
        table.insert(field("a"))
        table.insert(field("b"))
        table.insert(field("c"))
        #expect(table.insertCount == 3)
        #expect(table.field(atAbsolute: 0)?.name == "a")  // first inserted
        #expect(table.field(atAbsolute: 1)?.name == "b")
        #expect(table.field(atAbsolute: 2)?.name == "c")  // most recent
        #expect(table.field(atAbsolute: 3) == nil)  // never inserted
    }

    @Test("an absolute index keeps addressing the same entry as newer ones insert (§3.2.4)")
    func absoluteIndexStableAcrossInserts() {
        var table = QPACKDynamicTable(capacity: 4_096)
        table.insert(field("first"))
        let absoluteOfFirst = table.insertCount - 1
        for index in 0 ..< 10 { table.insert(field("filler\(index)")) }
        #expect(table.field(atAbsolute: absoluteOfFirst)?.name == "first")  // unchanged
    }

    // MARK: Base-relative indexing (§3.2.5)

    @Test("relative index 0 is the entry at absolute index Base-1 (§3.2.5)")
    func baseRelativeIndexing() {
        var table = QPACKDynamicTable(capacity: 4_096)
        table.insert(field("a"))  // absolute 0
        table.insert(field("b"))  // absolute 1
        table.insert(field("c"))  // absolute 2
        // With Base = 3 (= insertCount), relative 0 → absolute 2, relative 2 → absolute 0.
        #expect(table.field(base: 3, relativeIndex: 0)?.name == "c")
        #expect(table.field(base: 3, relativeIndex: 1)?.name == "b")
        #expect(table.field(base: 3, relativeIndex: 2)?.name == "a")
        #expect(table.field(base: 3, relativeIndex: 3) == nil)
        // A smaller Base addresses an earlier window: Base 2 → relative 0 = absolute 1.
        #expect(table.field(base: 2, relativeIndex: 0)?.name == "b")
    }

    // MARK: Post-base indexing (§3.2.6)

    @Test("post-base index 0 is the entry at absolute index Base (§3.2.6)")
    func postBaseIndexing() {
        var table = QPACKDynamicTable(capacity: 4_096)
        table.insert(field("a"))  // absolute 0
        table.insert(field("b"))  // absolute 1
        table.insert(field("c"))  // absolute 2
        // With Base = 1, post-base 0 → absolute 1, post-base 1 → absolute 2.
        #expect(table.field(base: 1, postBaseIndex: 0)?.name == "b")
        #expect(table.field(base: 1, postBaseIndex: 1)?.name == "c")
        #expect(table.field(base: 1, postBaseIndex: 2) == nil)  // absolute 3 not inserted
    }

    // MARK: Insert-point relative indexing (§3.2.4, encoder stream)

    @Test("insert-point relative index 0 is the most recently inserted entry (§3.2.4)")
    func insertPointRelativeIndexing() {
        var table = QPACKDynamicTable(capacity: 4_096)
        table.insert(field("a"))
        table.insert(field("b"))
        table.insert(field("c"))
        #expect(table.field(relativeToInsertPoint: 0)?.name == "c")  // newest
        #expect(table.field(relativeToInsertPoint: 2)?.name == "a")  // oldest live
        #expect(table.field(relativeToInsertPoint: 3) == nil)
    }

    // MARK: Eviction (§3.2.2)

    @Test("inserting past capacity evicts the oldest, preserving absolute indices (§3.2.2)")
    func evictsOldestPreservingAbsoluteIndices() {
        // Each "x"=… entry sizes 1 (name) + value + 32. Use 33-octet entries (1-char name, empty value)
        // and a capacity of 99 → at most 3 live entries.
        var table = QPACKDynamicTable(capacity: 99)
        table.insert(field("a"))  // absolute 0
        table.insert(field("b"))  // absolute 1
        table.insert(field("c"))  // absolute 2 — table full (3 × 33 = 99)
        #expect(table.count == 3)
        table.insert(field("d"))  // absolute 3 — evicts "a" (absolute 0)
        #expect(table.count == 3)
        #expect(table.insertCount == 4)
        #expect(table.field(atAbsolute: 0) == nil)  // "a" evicted
        #expect(table.field(atAbsolute: 1)?.name == "b")  // survivors keep their absolute index
        #expect(table.field(atAbsolute: 3)?.name == "d")
        #expect(table.oldestAbsoluteIndex == 1)
    }

    @Test("setCapacity shrinks the table by evicting the oldest entries (§3.2.3)")
    func setCapacityEvicts() {
        var table = QPACKDynamicTable(capacity: 99)
        table.insert(field("a"))
        table.insert(field("b"))
        table.insert(field("c"))
        table.setCapacity(33)  // room for one 33-octet entry
        #expect(table.count == 1)
        #expect(table.field(atAbsolute: 2)?.name == "c")  // the newest survives
        #expect(table.field(atAbsolute: 1) == nil)
        // Re-growing the capacity does not resurrect evicted entries (§3.2.3).
        table.setCapacity(4_096)
        #expect(table.count == 1)
    }

    // MARK: Capacity errors (§3.2.2)

    @Test("an entry larger than the whole capacity is rejected, table unchanged (§3.2.2)")
    func oversizedInsertRejected() {
        var table = QPACKDynamicTable(capacity: 40)  // fits a 1-char name (33) but not a long one
        let small = table.insert(field("a"))  // 33 ≤ 40
        #expect(small)
        let before = table
        let oversized = table.insert(field("toolongname", "value"))  // > 40 → rejected
        #expect(!oversized)
        #expect(table == before)  // unchanged (not emptied, unlike HPACK)
        #expect(table.field(atAbsolute: 0)?.name == "a")
    }

    @Test("duplicate copies an existing entry to the insert point (§4.3.4)")
    func duplicateCopiesEntry() {
        var table = QPACKDynamicTable(capacity: 4_096)
        table.insert(field("dup", "v"))  // absolute 0
        table.insert(field("other"))  // absolute 1
        let duplicated = table.duplicate(relativeIndex: 1)  // duplicate "dup" → absolute 2
        #expect(duplicated)
        #expect(table.insertCount == 3)
        #expect(table.field(atAbsolute: 2) == field("dup", "v"))
        let missing = table.duplicate(relativeIndex: 9)  // no such entry
        #expect(!missing)
    }
}
