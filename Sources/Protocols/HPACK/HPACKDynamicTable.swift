//
//  HPACKDynamicTable.swift
//  HPACK
//
//  RFC 7541 §2.3.2 / §4 — the HPACK dynamic table: a FIFO of recently inserted fields that, together
//  with the static table, forms one index address space (§2.3.3). Indices 1...61 are static; 62 and
//  up are dynamic with 62 addressing the most recently inserted entry. Insertion evicts the oldest
//  entries to honor the size bound (§4.4), and an entry larger than the whole table empties it.
//
//  Backed by a growable **circular buffer** (audit P8): adding writes at the tail and evicting advances
//  the head, both O(1) — replacing the newest-first `insert(at: 0)`, which shifted every live entry on
//  every insert. `field(at:)` (the decoder's index → field) is O(1); the encoder's exact/name lookups
//  (``index(of:)`` / ``index(forName:)``) are O(1) via two hash indices keyed on each entry's
//  absolute insertion **sequence** — a monotonic counter that survives the relative-index shift every
//  add causes and the ring's physical relocation, so the maps need no rewrite on insert. Capacity
//  doubles only when the live count would exceed it, settling at the table's high-water mark
//  (≈ `maxSize / 32` entries, since every entry is ≥ 32 octets).
//

public import HTTPCore

/// The RFC 7541 §2.3.2 dynamic table (with the combined §2.3.3 index lookup).
public struct HPACKDynamicTable: Sendable, Equatable {
    /// Circular backing store: `slots[head]` is the oldest live entry, `slots[(head + count - 1) mod
    /// capacity]` the newest (index 62); free slots hold `nil`.
    private var slots: [HPACKField?] = []
    /// Index of the oldest live entry (meaningless when ``count`` is 0).
    private var head = 0

    /// Total entries ever inserted — the monotonic clock the index maps key on (never reset on eviction).
    private var insertCount = 0
    /// Field → the absolute insertion sequence of the newest entry equal to it (O(1) exact lookup).
    private var exactSequence: [HPACKField: Int] = [:]
    /// Name → the absolute insertion sequence of the newest entry with that name (O(1) name lookup).
    private var nameSequence: [String: Int] = [:]

    /// The number of entries currently held.
    public private(set) var count = 0

    /// The current table size in octets (sum of entry sizes, RFC 7541 §4.1).
    public private(set) var size = 0

    /// The maximum table size in octets (RFC 7541 §4.2); changed via ``setMaxSize(_:)``.
    public private(set) var maxSize: Int

    /// Creates an empty dynamic table bounded by `maxSize` octets.
    public init(maxSize: Int) {
        self.maxSize = maxSize
    }

    /// Whether the table currently holds no entries.
    public var isEmpty: Bool {
        // swiftlint:disable:next empty_count - `count` is the entry count, not a Collection's
        count == 0
    }

    /// The backing slot holding the entry `position` places from the newest (`0` is the newest).
    ///
    /// Callers pass `position` in `0 ..< count`, so the result is always a live slot.
    private func slot(fromNewest position: Int) -> Int {
        // The newest entry is at `head + count - 1`; step back `position`. The value lies in
        // `[head, head + count - 1] ⊂ [0, head + capacity - 1] < 2·capacity`, so one wrap suffices.
        var index = head + count - 1 - position
        if index >= slots.count {
            index -= slots.count
        }
        return index
    }

    /// The current relative HPACK index of the (still-live) entry inserted at absolute `sequence`.
    private func hpackIndex(forSequence sequence: Int) -> Int {
        // The newest entry (`sequence == insertCount - 1`) is index 62; older entries count up from there.
        HPACKStaticTable.count + 1 + (insertCount - 1 - sequence)
    }

    /// Returns the field at combined HPACK index `index`, or `nil` if it addresses no entry.
    ///
    /// `1...61` index the static table; `62...` index the dynamic table, newest first (§2.3.3).
    public func field(at index: Int) -> HPACKField? {
        if let staticField = HPACKStaticTable.field(at: index) {
            return staticField
        }
        let position = index - HPACKStaticTable.count - 1
        guard position >= 0, position < count else {
            return nil
        }
        return slots[slot(fromNewest: position)]
    }

    /// The combined HPACK index of the newest entry exactly equal to `field`, or nil — O(1) (§2.3.3).
    public func index(of field: HPACKField) -> Int? {
        guard let sequence = exactSequence[field] else {
            return nil
        }
        return hpackIndex(forSequence: sequence)
    }

    /// The combined HPACK index of the newest entry whose name is `name`, or nil — O(1).
    public func index(forName name: String) -> Int? {
        guard let sequence = nameSequence[name] else {
            return nil
        }
        return hpackIndex(forSequence: sequence)
    }

    /// Inserts `field` as the newest entry, first evicting the oldest entries to make room (§4.4).
    ///
    /// If `field` is larger than the entire table, the table is emptied and nothing is inserted —
    /// not an error, per §4.4.
    public mutating func add(_ field: HPACKField) {
        evict(untilRoomFor: field.tableSize)
        guard field.tableSize <= maxSize else {
            return
        }
        reserveOneMore()
        // Write the new entry at the tail (the free slot just past the newest).
        slots[(head + count) % slots.count] = field
        // Index this insertion by its absolute sequence. A later duplicate (or same name) overwrites the
        // sequence, so both maps always resolve to the newest matching entry (§2.3.3 numbering).
        exactSequence[field] = insertCount
        nameSequence[field.name] = insertCount
        insertCount += 1
        count += 1
        size += field.tableSize
    }

    /// Sets a new maximum size, evicting the oldest entries until the table fits (RFC 7541 §6.3).
    public mutating func setMaxSize(_ newMaxSize: Int) {
        maxSize = newMaxSize
        evict(untilRoomFor: 0)
    }

    /// Evicts the oldest entries until `incoming` more octets would fit within ``maxSize``.
    private mutating func evict(untilRoomFor incoming: Int) {
        while !isEmpty, size + incoming > maxSize {
            guard let oldest = slots[head] else {
                break  // unreachable: `head` is a live slot while `count > 0`, but stay trap-free
            }
            // The oldest live entry's absolute sequence (live sequences are `insertCount - count ..<
            // insertCount`). Drop its index entries — but only when a newer duplicate has not already
            // overwritten them to a later sequence (FIFO evicts oldest-first, so a survivor is newer).
            let evictedSequence = insertCount - count
            if exactSequence[oldest] == evictedSequence {
                exactSequence[oldest] = nil
            }
            if nameSequence[oldest.name] == evictedSequence {
                nameSequence[oldest.name] = nil
            }
            size -= oldest.tableSize
            slots[head] = nil  // release the evicted entry's storage
            head += 1
            if head == slots.count {
                head = 0
            }
            count -= 1
        }
    }

    /// Ensures there is a free slot for one more entry, growing (and linearizing) the ring if full.
    private mutating func reserveOneMore() {
        guard count == slots.count else {
            return
        }
        let grownCapacity = max(8, slots.count * 2)
        var grown = [HPACKField?](repeating: nil, count: grownCapacity)
        // Re-lay the live entries oldest→newest at `[0 ..< count]`, then reset the head to 0.
        for position in 0 ..< count {
            grown[position] = slots[slot(fromNewest: count - 1 - position)]
        }
        slots = grown
        head = 0
    }

    /// Two tables are equal iff they bound the same size and hold the same entries newest-first —
    /// compared logically, independent of where the ring's `head` (or the absolute clock) happens to sit.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        guard lhs.maxSize == rhs.maxSize, lhs.size == rhs.size, lhs.count == rhs.count else {
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
