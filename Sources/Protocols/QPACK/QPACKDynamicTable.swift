//
//  QPACKDynamicTable.swift
//  QPACK
//
//  RFC 9204 §3.2 — the QPACK dynamic table: a FIFO of inserted fields that, unlike HPACK, occupies an
//  index space **separate** from the 99-entry static table (§3.2.4). Each insert is given a permanent,
//  ever-incrementing *absolute index* (§3.2.4): the first insert is absolute 0, and an entry's absolute
//  index never changes even as older entries are evicted. Field-line representations address entries
//  *relative to a Base* (§3.2.5/§3.2.6) and encoder-stream instructions address them *relative to the
//  insert point* (§3.2.4); getting that arithmetic exact is the known QPACK interop trap, so each
//  conversion below cites its section. Insertion evicts the oldest entries to honor the capacity bound
//  (§3.2.2); an entry larger than the whole capacity is rejected (a §3.2.2 error, not an empty-table).
//
//  Backed by a growable **circular buffer**, the same shape as ``HPACKDynamicTable``: inserting writes
//  at the tail and evicting advances the head, both O(1) — replacing the newest-first `insert(at: 0)`,
//  which shifted every live entry on every insert. `field(atAbsolute:)`, and so every §3.2.5/§3.2.6
//  conversion layered on it, is O(1); the encoder's exact and name lookups (``absoluteIndex(of:)`` /
//  ``absoluteIndex(forName:)``) are O(1) via two hash indices. HPACK has to key those indices on a
//  separate monotonic insertion counter, because its indices shift on every add — QPACK gets that key
//  for free: §3.2.4 guarantees an absolute index never changes, so the **absolute index is itself the
//  key**, and neither eviction nor the ring's physical relocation forces a map rewrite. The ring
//  doubles only when the live count would exceed it, settling at the table's high-water mark
//  (≈ `capacity / 32` entries, since every entry is ≥ 32 octets).
//
//  This is the sans-I/O data structure only. Reference tracking against eviction (an entry referenced
//  by an unacknowledged section MUST NOT be evicted, §2.1.3) and blocked-stream gating are connection
//  concerns layered above it.
//

public import HTTPCore

/// The RFC 9204 §3.2 QPACK dynamic table — a separate index space with absolute/Base/post-base lookup.
public struct QPACKDynamicTable: Sendable, Equatable {
    /// Circular backing store: `slots[head]` is the oldest live entry, `slots[(head + count - 1) mod
    /// slots.count]` the most recently inserted one; free slots hold `nil`.
    private var slots: [HeaderField?] = []
    /// Index of the oldest live entry (meaningless when ``count`` is 0).
    private var head = 0

    /// Field → the absolute index of the newest entry equal to it (the O(1) §3.2.4 exact lookup).
    private var exactAbsolute: [HeaderField: Int] = [:]
    /// Name → the absolute index of the newest entry with that name (the O(1) §4.5.4 name lookup).
    private var nameAbsolute: [String: Int] = [:]

    /// The number of entries currently held (insertCount minus evicted).
    public private(set) var count = 0

    /// The current table size in octets (sum of entry sizes, RFC 9204 §3.2.1).
    public private(set) var size = 0

    /// The maximum table size in octets — `SETTINGS_QPACK_MAX_TABLE_CAPACITY` / Set Capacity (§3.2.3).
    public private(set) var capacity: Int

    /// The total number of entries ever inserted (RFC 9204 §3.2.4): the next insert takes absolute
    /// index `insertCount`, and the Required Insert Count of a section is bounded by this.
    public private(set) var insertCount = 0

    /// Creates an empty dynamic table bounded by `capacity` octets.
    public init(capacity: Int) {
        self.capacity = capacity
    }

    /// Whether the table currently holds no entries.
    public var isEmpty: Bool {
        // swiftlint:disable:next empty_count - `count` is the entry count, not a Collection's
        count == 0
    }

    /// The absolute index of the oldest still-present entry (RFC 9204 §3.2.4); equals `insertCount`
    /// when the table is empty (no entry is addressable).
    public var oldestAbsoluteIndex: Int { insertCount - count }

    /// The backing slot holding the entry `position` places from the newest (`0` is the newest).
    ///
    /// Callers pass `position` in `0 ..< count`, so the result is always a live slot.
    private func slot(fromNewest position: Int) -> Int {
        // The newest entry is at `head + count - 1`; step back `position`. The value lies in
        // `[head, head + count - 1] ⊂ [0, head + slots.count - 1] < 2·slots.count`, so one wrap suffices.
        var index = head + count - 1 - position
        if index >= slots.count {
            index -= slots.count
        }
        return index
    }

    /// Returns the entry at *absolute* index `absolute` (RFC 9204 §3.2.4), or nil if it was never
    /// inserted or has been evicted.
    public func field(atAbsolute absolute: Int) -> HeaderField? {
        // The entry with absolute index `absolute` sits `insertCount - 1 - absolute` back from newest.
        let position = insertCount - 1 - absolute
        guard position >= 0, position < count else {
            return nil
        }
        return slots[slot(fromNewest: position)]
    }

    /// Returns the entry a field-line representation addresses *relative to `base`* (RFC 9204 §3.2.5).
    ///
    /// Relative index 0 is the entry with absolute index `base - 1`; nil if it addresses no live entry.
    public func field(base: Int, relativeIndex: Int) -> HeaderField? {
        field(atAbsolute: base - 1 - relativeIndex)
    }

    /// Returns the entry a *post-base* representation addresses (RFC 9204 §3.2.6).
    ///
    /// Post-base index 0 is the entry with absolute index `base`; nil if it addresses no live entry.
    public func field(base: Int, postBaseIndex: Int) -> HeaderField? {
        field(atAbsolute: base + postBaseIndex)
    }

    /// Returns the entry an *encoder-stream* instruction addresses relative to the insert point.
    ///
    /// RFC 9204 §3.2.4 — relative index 0 is the most recently inserted entry (absolute
    /// `insertCount - 1`); used by Insert With Name Reference (§4.3.2) and Duplicate (§4.3.4).
    public func field(relativeToInsertPoint relativeIndex: Int) -> HeaderField? {
        field(atAbsolute: insertCount - 1 - relativeIndex)
    }

    /// The absolute index of the newest entry exactly equal to `field`, or nil if none is held — O(1).
    ///
    /// RFC 9204 §3.2.4 — lets an encoder reuse an already-inserted field as a dynamic indexed reference.
    /// The most recently inserted match (highest absolute index) wins.
    public func absoluteIndex(of field: HeaderField) -> Int? {
        exactAbsolute[field]
    }

    /// The absolute index of the newest entry whose name is `name`, or nil if none is held — O(1).
    ///
    /// RFC 9204 §4.5.4 — lets an encoder emit a Literal Field Line With Name Reference against the
    /// dynamic table when the name recurs but the value does not.
    public func absoluteIndex(forName name: String) -> Int? {
        nameAbsolute[name]
    }

    /// Whether `field` would fit without evicting any existing entry (room within ``capacity``).
    ///
    /// A never-evicting encoder checks this before inserting, so it never displaces an entry that a
    /// pending, unacknowledged section might still reference (RFC 9204 §2.1.3).
    public func hasRoom(for field: HeaderField) -> Bool {
        size + field.tableSize <= capacity
    }

    /// Inserts `field` as the newest entry, first evicting the oldest entries to make room (§3.2.2).
    ///
    /// Returns false without inserting if `field` is larger than the whole capacity — a §3.2.2 error the
    /// caller maps to QPACK_ENCODER_STREAM_ERROR (the table is left unchanged, not emptied as in HPACK).
    @discardableResult
    public mutating func insert(_ field: HeaderField) -> Bool {
        // Checked before evicting anything, so a rejected insert leaves the table untouched (§3.2.2).
        guard field.tableSize <= capacity else {
            return false
        }
        evict(untilRoomFor: field.tableSize)
        reserveOneMore()
        // Write the new entry at the tail (the free slot just past the newest).
        slots[(head + count) % slots.count] = field
        // File both index entries under this insert's absolute index. A later duplicate — or a later
        // entry sharing the name — overwrites the key, so each map always resolves to the newest match.
        exactAbsolute[field] = insertCount
        nameAbsolute[field.name] = insertCount
        insertCount += 1
        count += 1
        size += field.tableSize
        return true
    }

    /// Inserts a duplicate of an existing entry addressed relative to the insert point (§4.3.4).
    ///
    /// Returns false if `relativeIndex` addresses no live entry; otherwise inserts a copy (its tableSize
    /// is unchanged, so it always fits if the original did — but it is re-evaluated against eviction).
    @discardableResult
    public mutating func duplicate(relativeIndex: Int) -> Bool {
        guard let field = field(relativeToInsertPoint: relativeIndex) else {
            return false
        }
        return insert(field)
    }

    /// Sets a new capacity, evicting the oldest entries until the table fits (RFC 9204 §3.2.3).
    public mutating func setCapacity(_ newCapacity: Int) {
        capacity = newCapacity
        evict(untilRoomFor: 0)
    }

    /// Evicts exactly the oldest entry (lowest absolute index), returning it, or nil if empty.
    ///
    /// RFC 9204 §3.2.2 — for an encoder that gates eviction on its own reference tracking (§2.1.3): it
    /// checks ``oldestAbsoluteIndex`` is unreferenced before calling this, rather than letting
    /// ``insert(_:)`` evict blindly. `insertCount` is unchanged, so survivors keep their absolute indices.
    @discardableResult
    public mutating func evictOldest() -> HeaderField? {
        guard !isEmpty, let oldest = slots[head] else {
            return nil
        }
        // The evicted entry's absolute index is the key its index-map entries were filed under. Drop
        // them — but only where a newer duplicate has not already claimed the key, which eviction being
        // strictly oldest-first makes easy to test: a survivor holding the key is by definition newer.
        let evictedAbsolute = insertCount - count
        if exactAbsolute[oldest] == evictedAbsolute {
            exactAbsolute[oldest] = nil
        }
        if nameAbsolute[oldest.name] == evictedAbsolute {
            nameAbsolute[oldest.name] = nil
        }
        size -= oldest.tableSize
        slots[head] = nil  // release the evicted entry's storage
        head += 1
        if head == slots.count {
            head = 0
        }
        count -= 1
        return oldest
    }

    /// Evicts the oldest entries until `incoming` more octets would fit within ``capacity`` (§3.2.2).
    ///
    /// Eviction removes the entry with the *lowest* absolute index; `insertCount` is unchanged, so every
    /// surviving entry keeps its absolute index (the §3.2.4 invariant the lookups above rely on).
    private mutating func evict(untilRoomFor incoming: Int) {
        while size + incoming > capacity {
            guard evictOldest() != nil else {
                return  // the table is already empty — no further eviction can free anything
            }
        }
    }

    /// Ensures there is a free slot for one more entry, growing (and linearizing) the ring if full.
    private mutating func reserveOneMore() {
        guard count == slots.count else {
            return
        }
        let grownCapacity = max(8, slots.count * 2)
        var grown = [HeaderField?](repeating: nil, count: grownCapacity)
        // Re-lay the live entries oldest→newest at `[0 ..< count]`, then reset the head to 0.
        for position in 0 ..< count {
            grown[position] = slots[slot(fromNewest: count - 1 - position)]
        }
        slots = grown
        head = 0
    }

    /// Two tables are equal iff they bound the same capacity and hold the same entries at the same
    /// absolute indices — compared logically, independent of where the ring's `head` happens to sit.
    ///
    /// The synthesized conformance would compare the backing ring, calling two tables with identical
    /// logical contents unequal purely because they grew or evicted along different routes. Unlike
    /// HPACK, `insertCount` *is* compared: an absolute index is observable through
    /// ``field(atAbsolute:)`` (§3.2.4), so the same contents at a different insert count are a
    /// different table.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        guard lhs.capacity == rhs.capacity, lhs.size == rhs.size, lhs.count == rhs.count,
            lhs.insertCount == rhs.insertCount
        else {
            return false
        }
        for position in 0 ..< lhs.count {
            let left = lhs.slots[lhs.slot(fromNewest: position)]
            let right = rhs.slots[rhs.slot(fromNewest: position)]
            if left != right {
                return false
            }
        }
        return true
    }
}
