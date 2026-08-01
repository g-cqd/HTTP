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

    // MARK: Encoder lookups (§3.2.4 exact, §4.5.4 name)

    @Test("the name index finds the newest entry with a given name (§4.5.4)")
    func nameIndexFindsNewestEntry() {
        var table = QPACKDynamicTable(capacity: 4_096)
        table.insert(field("cookie", "a=1"))  // absolute 0
        table.insert(field("accept", "*/*"))  // absolute 1
        table.insert(field("cookie", "b=2"))  // absolute 2
        #expect(table.absoluteIndex(forName: "cookie") == 2)  // the newest same-name entry wins
        #expect(table.absoluteIndex(forName: "accept") == 1)
        #expect(table.absoluteIndex(forName: "absent") == nil)
        // A name match is not an exact match — the older entry keeps its own exact mapping.
        #expect(table.absoluteIndex(of: field("cookie", "a=1")) == 0)
    }

    @Test("the exact/name indices match a brute-force scan across duplicates and eviction (§3.2.4)")
    func indexLookupsMatchBruteForce() {
        // A small capacity forces eviction while repeated names and values force duplicate entries —
        // the cases an absolute-index-keyed hash index must get right (the newest match wins, and an
        // evicted entry's mapping is dropped only when no newer duplicate already replaced it).
        var table = QPACKDynamicTable(capacity: 200)
        let names = ["a", "bb", "ccc", "a", "bb"]
        for round in 0 ..< 16 {
            table.insert(field(names[round % names.count], "v\(round % 4)"))

            // Reference: scan live entries newest-first and return the first absolute index matching.
            func newestAbsolute(where matches: (HeaderField) -> Bool) -> Int? {
                for offset in 0 ..< table.count {
                    let absolute = table.insertCount - 1 - offset
                    if let entry = table.field(atAbsolute: absolute), matches(entry) {
                        return absolute
                    }
                }
                return nil
            }

            for offset in 0 ..< table.count {
                guard let live = table.field(atAbsolute: table.insertCount - 1 - offset) else {
                    continue
                }
                #expect(table.absoluteIndex(of: live) == newestAbsolute { $0 == live })
                let byName = newestAbsolute { $0.name == live.name }
                #expect(table.absoluteIndex(forName: live.name) == byName)
                // The exact lookup must round-trip back through §3.2.4 to an equal field.
                #expect(table.absoluteIndex(of: live).flatMap(table.field(atAbsolute:)) == live)
            }
            #expect(table.absoluteIndex(of: field("zzz", "absent")) == nil)
            #expect(table.absoluteIndex(forName: "zzz") == nil)
        }
    }

    @Test("evicting an entry keeps the mapping a newer duplicate already owns (§3.2.2)")
    func evictionKeepsNewerDuplicateMapping() {
        var table = QPACKDynamicTable(capacity: 4_096)
        table.insert(field("d", "v"))  // absolute 0
        table.insert(field("x"))  // absolute 1
        table.insert(field("d", "v"))  // absolute 2 — a duplicate of absolute 0
        #expect(table.absoluteIndex(of: field("d", "v")) == 2)  // the newest duplicate wins
        table.evictOldest()  // drops absolute 0, whose mapping absolute 2 already took over
        #expect(table.absoluteIndex(of: field("d", "v")) == 2)  // still reachable
        #expect(table.absoluteIndex(forName: "d") == 2)
        table.evictOldest()  // drops absolute 1
        #expect(table.absoluteIndex(forName: "x") == nil)
        table.evictOldest()  // drops absolute 2 — now the mapping must go with it
        #expect(table.absoluteIndex(of: field("d", "v")) == nil)
        #expect(table.absoluteIndex(forName: "d") == nil)
        #expect(table.isEmpty)
    }

    @Test("setCapacity eviction drops the index mappings of the entries it removes (§3.2.3)")
    func setCapacityDropsStaleIndexMappings() {
        var table = QPACKDynamicTable(capacity: 4_096)
        table.insert(field("a"))  // absolute 0
        table.insert(field("b"))  // absolute 1
        table.setCapacity(33)  // room for one 33-octet entry — "a" is evicted
        #expect(table.absoluteIndex(of: field("a")) == nil)
        #expect(table.absoluteIndex(forName: "a") == nil)
        #expect(table.absoluteIndex(of: field("b")) == 1)  // survivors keep their absolute index
        #expect(table.absoluteIndex(forName: "b") == 1)
    }

    // MARK: Equality over logical contents

    @Test("equality compares logical contents, not the backing ring's physical layout")
    func equalityIsLogicalNotPhysical() {
        // Two tables reach an identical logical state — capacity 99, insertCount 12, the three newest
        // entries live — by different routes, so their rings differ in length and head offset:
        // `churned` evicted as it went and never grew past its first ring, while `shrunk` held all
        // twelve (growing, which re-lays the ring from index 0) before evicting down. A synthesized
        // `Equatable` over the ring's storage would wrongly call these two unequal.
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"]
        var churned = QPACKDynamicTable(capacity: 99)  // 3 × 33 octets
        for name in names {
            churned.insert(field(name))
        }
        var shrunk = QPACKDynamicTable(capacity: 4_096)
        for name in names {
            shrunk.insert(field(name))
        }
        shrunk.setCapacity(99)

        #expect(churned.count == 3)
        #expect(churned.insertCount == 12)
        #expect(churned == shrunk)

        // Absolute indices are observable (§3.2.4), so identical *contents* at a different insert
        // count are still not equal — `field(atAbsolute:)` disagrees between the two tables.
        var fresh = QPACKDynamicTable(capacity: 99)
        for name in ["a", "b", "c"] {
            fresh.insert(field(name))
        }
        var recycled = QPACKDynamicTable(capacity: 99)
        for name in ["z", "a", "b", "c"] {
            recycled.insert(field(name))  // "z" is evicted, leaving the same three entries live
        }
        #expect(fresh.field(atAbsolute: 0)?.name == "a")
        #expect(recycled.field(atAbsolute: 0) == nil)  // here "a" is absolute 1, not 0
        #expect(fresh != recycled)
    }
}
