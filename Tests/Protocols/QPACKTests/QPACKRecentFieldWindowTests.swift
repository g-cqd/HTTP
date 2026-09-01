//
//  QPACKRecentFieldWindowTests.swift
//  QPACKTests
//
//  The insert-on-second-use window behind the RFC 9204 §4.3 encoder. These tests pin the FIFO
//  semantics the encoder relies on — a field must recur while it is still in the window to be worth a
//  dynamic-table insert — and the staleness trap the position index introduces: a field that is
//  forgotten and then seen again must not be dropped when its ORIGINAL slot is later recycled.
//
//  `recordSighting(of:)` is mutating, so every result is hoisted into a `let` before `#expect` — the
//  macro cannot call a mutating member on the value it captures.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("QPACK recent-field window — the §4.3 insert-on-second-use heuristic")
struct QPACKRecentFieldWindowTests {
    private func field(_ name: String) -> HeaderField {
        HeaderField(name: name, value: "v")
    }

    @Test("a first sighting is not a repeat, and the next sighting of it is")
    func secondSightingIsARepeat() {
        var window = QPACKRecentFieldWindow(limit: 4)
        let first = window.recordSighting(of: field("a"))
        let second = window.recordSighting(of: field("a"))
        let other = window.recordSighting(of: field("b"))
        #expect(!first)
        #expect(second)  // recurs → worth a dynamic-table insert
        #expect(!other)
    }

    @Test("a sighting pushed out by newer ones counts as a first sighting again")
    func oldestSightingIsEvicted() {
        var window = QPACKRecentFieldWindow(limit: 4)
        for name in ["a", "b", "c", "d"] {
            let seen = window.recordSighting(of: field(name))
            #expect(!seen)
        }
        let stillHeld = window.recordSighting(of: field("a"))
        #expect(stillHeld)  // inside the window
        // A repeat does not refresh position, so "a" is still the oldest: four more distinct
        // sightings recycle its slot.
        for name in ["e", "f", "g", "h"] {
            let seen = window.recordSighting(of: field(name))
            #expect(!seen)
        }
        let afterEviction = window.recordSighting(of: field("a"))
        #expect(!afterEviction)  // pushed out → a first sighting once more
    }

    @Test("forgetting a field drops it, so its next sighting is a first sighting")
    func forgettingDropsTheField() {
        var window = QPACKRecentFieldWindow(limit: 4)
        let first = window.recordSighting(of: field("a"))
        window.forget(field("a"))  // the encoder forgets a field once it lives in the table
        let afterForget = window.recordSighting(of: field("a"))
        window.forget(field("absent"))  // forgetting something absent is a no-op
        let afterNoOp = window.recordSighting(of: field("a"))
        #expect(!first)
        #expect(!afterForget)
        #expect(afterNoOp)
    }

    @Test("recycling a forgotten field's original slot must not drop its live re-sighting")
    func staleSlotDoesNotEvictTheLiveEntry() {
        // The staleness trap: "a" is recorded at slot 0, forgotten, then recorded again at a later
        // slot. When the ring recycles slot 0, that slot no longer speaks for "a" — dropping "a"
        // there would silently disable the heuristic for it.
        var window = QPACKRecentFieldWindow(limit: 4)
        _ = window.recordSighting(of: field("a"))  // slot 0
        window.forget(field("a"))
        let reRecorded = window.recordSighting(of: field("a"))  // recorded again, at a later slot
        #expect(!reRecorded)
        for name in ["b", "c", "d"] {  // recycles slot 0, but not "a"'s current slot
            let seen = window.recordSighting(of: field(name))
            #expect(!seen)
        }
        let stillLive = window.recordSighting(of: field("a"))
        #expect(stillLive)  // slot 0 was stale, so "a" survived
    }

    @Test("the window retains exactly its limit of distinct sightings", arguments: [1, 2, 8, 64])
    func windowRetainsExactlyItsLimit(limit: Int) {
        var window = QPACKRecentFieldWindow(limit: limit)
        for index in 0 ..< (limit * 3) {
            let seen = window.recordSighting(of: field("f\(index)"))
            #expect(!seen)
        }
        // The most recent `limit` sightings are retained...
        for index in (limit * 2) ..< (limit * 3) {
            let seen = window.recordSighting(of: field("f\(index)"))
            #expect(seen)
        }
        // ...and everything older has been pushed out.
        for index in 0 ..< limit {
            let seen = window.recordSighting(of: field("f\(index)"))
            #expect(!seen)
        }
    }
}
