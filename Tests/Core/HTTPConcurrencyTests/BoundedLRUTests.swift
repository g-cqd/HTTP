//
//  BoundedLRUTests.swift
//  HTTPConcurrencyTests
//
//  The hard-bound guarantees of ``BoundedLRU`` — the regression suite for audit finding 9 ("bounded"
//  maps can exceed their caps, CWE-400 / CWE-770) and finding 14 (the class-node recency list held a
//  reference cycle, CWE-401). The capacity bound is asserted under *both* overflow policies, because
//  the hand-rolled prune it replaces enforced it under neither, and a `deinit` counter proves the
//  index-linked slab releases every value it was ever handed.
//

import HTTPConcurrency
import Testing

@Test(
    "capacity is a hard bound under every overflow policy",
    arguments: BoundedLRU<Int, Int>.Overflow.allCases
)
func capacityIsAHardBound(policy: BoundedLRU<Int, Int>.Overflow) {
    var map = BoundedLRU<Int, Int>(capacity: 8, overflow: policy)
    for key in 0 ..< 1_000 {
        map.insert(key, forKey: key)
        #expect(map.count <= 8)
    }
    #expect(map.count == 8)
}

@Test("reject keeps every tracked entry and refuses the newcomer")
func rejectProtectsIncumbents() {
    var map = BoundedLRU<Int, Int>(capacity: 3, overflow: .reject)
    for key in 0 ..< 3 {
        #expect(map.insert(key, forKey: key) == .inserted(evicted: 0))
    }
    #expect(map.insert(99, forKey: 99) == .rejected)
    #expect(map.value(forKey: 99) == nil)
    for key in 0 ..< 3 {
        #expect(map.value(forKey: key) == key)
    }
}

@Test("eviction drops exactly the least-recently-used entry")
func evictsLeastRecentlyUsed() {
    var map = BoundedLRU<Int, Int>(capacity: 3)
    map.insert(0, forKey: 0)
    map.insert(1, forKey: 1)
    map.insert(2, forKey: 2)
    #expect(map.touchedValue(forKey: 0) == 0)  // 1 is now the least-recently-used
    #expect(map.insert(3, forKey: 3) == .inserted(evicted: 1))
    #expect(map.value(forKey: 1) == nil)
    #expect(map.value(forKey: 0) == 0)
    #expect(map.value(forKey: 2) == 2)
    #expect(map.value(forKey: 3) == 3)
}

@Test("a plain read does not reorder recency")
func readDoesNotReorder() {
    var map = BoundedLRU<Int, Int>(capacity: 2)
    map.insert(0, forKey: 0)
    map.insert(1, forKey: 1)
    #expect(map.value(forKey: 0) == 0)  // no promotion — 0 stays the eviction candidate
    map.insert(2, forKey: 2)
    #expect(map.value(forKey: 0) == nil)
    #expect(map.value(forKey: 1) == 1)
}

@Test("withValue mutates in place, promotes, and reports a miss as nil")
func withValueMutatesAndPromotes() {
    var map = BoundedLRU<Int, Int>(capacity: 2)
    map.insert(10, forKey: 0)
    map.insert(20, forKey: 1)
    #expect(map.withValue(forKey: 0) { $0 += 5 } != nil)
    #expect(map.value(forKey: 0) == 15)
    #expect(map.withValue(forKey: 404) { $0 += 1 } == nil)
    map.insert(30, forKey: 2)  // 1 is the least-recently-used after the withValue promotion
    #expect(map.value(forKey: 1) == nil)
    #expect(map.value(forKey: 0) == 15)
}

@Test("cost tracks insertion, replacement and removal, and returns to zero after removeAll")
func costAccounting() {
    var map = BoundedLRU<Int, Int>(capacity: 16, maxCost: 1_000)
    map.insert(0, forKey: 0, cost: 100)
    map.insert(1, forKey: 1, cost: 250)
    #expect(map.cost == 350)
    #expect(map.insert(2, forKey: 1, cost: 50) == .replaced)
    #expect(map.cost == 150)
    #expect(map.removeValue(forKey: 0) == 0)
    #expect(map.cost == 50)
    map.removeAll()
    #expect(map.cost == 0)
    #expect(map.isEmpty)
}

@Test("the cost bound evicts least-recently-used entries to stay under maxCost")
func costBoundEvicts() {
    var map = BoundedLRU<Int, Int>(capacity: 100, maxCost: 300)
    map.insert(0, forKey: 0, cost: 100)
    map.insert(1, forKey: 1, cost: 100)
    map.insert(2, forKey: 2, cost: 100)
    #expect(map.insert(3, forKey: 3, cost: 150) == .inserted(evicted: 2))
    #expect(map.cost == 250)
    #expect(map.value(forKey: 0) == nil)
    #expect(map.value(forKey: 1) == nil)
    #expect(map.value(forKey: 2) == 2)
}

@Test("an entry whose own cost exceeds maxCost is refused")
func oversizedEntryIsRefused() {
    var map = BoundedLRU<Int, Int>(capacity: 10, maxCost: 100)
    #expect(map.insert(0, forKey: 0, cost: 101) == .rejected)
    #expect(map.isEmpty)
    #expect(map.cost == 0)
}

@Test("reclaim sweeps a bounded number of slots from the least-recently-used end")
func reclaimIsBounded() {
    var map = BoundedLRU<Int, Int>(capacity: 100)
    for key in 0 ..< 50 {
        map.insert(key, forKey: key)
    }
    var scanned = 0
    let reclaimed = map.reclaim(scanning: 10) { _, _ in
        scanned += 1
        return true
    }
    #expect(scanned == 10)  // never the whole map, however large it has grown
    #expect(reclaimed == 10)
    #expect(map.count == 40)
    #expect(map.value(forKey: 0) == nil)  // swept from the least-recently-used end
    #expect(map.value(forKey: 9) == nil)
    #expect(map.value(forKey: 10) == 10)
}

@Test("reclaim keeps the entries its predicate rejects")
func reclaimIsSelective() {
    var map = BoundedLRU<Int, Int>(capacity: 100)
    for key in 0 ..< 10 {
        map.insert(key, forKey: key)
    }
    #expect(map.reclaim(scanning: 10) { key, _ in key.isMultiple(of: 2) } == 5)
    #expect(map.count == 5)
    #expect(map.value(forKey: 3) == 3)
    #expect(map.value(forKey: 4) == nil)
}

/// The CWE-401 probe: every value handed to the map must eventually deallocate.
///
/// Serialized because the tracer's deallocation counter is process-wide.
@Suite("BoundedLRU — value lifetime (CWE-401)", .serialized)
struct BoundedLRUValueLifetimeTests {
    @Test(
        "dropping the map deallocates every value it was handed",
        arguments: BoundedLRU<Int, Tracer>.Overflow.allCases
    )
    func droppingDeallocatesEveryValue(policy: BoundedLRU<Int, Tracer>.Overflow) {
        Tracer.resetDeallocationCount()
        do {
            var map = BoundedLRU<Int, Tracer>(capacity: 64, overflow: policy)
            for key in 0 ..< 200 {
                map.insert(Tracer(key), forKey: key)
            }
            map.removeValue(forKey: 63)
            _ = map.touchedValue(forKey: 10)
        }
        // Evicted, rejected, explicitly removed, or released with the map — all 200 are gone. A
        // `prev`/`next` cycle between class nodes would strand every unlinked one forever.
        #expect(Tracer.deallocationCount == 200)
    }

    @Test("removeAll releases every value")
    func removeAllReleasesValues() {
        Tracer.resetDeallocationCount()
        var map = BoundedLRU<Int, Tracer>(capacity: 64)
        for key in 0 ..< 32 {
            map.insert(Tracer(key), forKey: key)
        }
        #expect(Tracer.deallocationCount == 0)
        map.removeAll()
        #expect(Tracer.deallocationCount == 32)
        #expect(map.isEmpty)
    }

    @Test("a removed value is released, not stranded in the freed slot")
    func removedValueIsReleased() {
        Tracer.resetDeallocationCount()
        var map = BoundedLRU<Int, Tracer>(capacity: 4)
        map.insert(Tracer(0), forKey: 0)
        map.removeValue(forKey: 0)
        #expect(Tracer.deallocationCount == 1)
        map.insert(Tracer(1), forKey: 1)  // reuses the freed slot
        #expect(map.value(forKey: 1)?.label == 1)
        #expect(map.count == 1)
    }
}
