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
//  This is the sans-I/O data structure only. Reference tracking against eviction (an entry referenced
//  by an unacknowledged section MUST NOT be evicted, §2.1.3) and blocked-stream gating are connection
//  concerns layered above it.
//

public import HTTPCore

/// The RFC 9204 §3.2 QPACK dynamic table — a separate index space with absolute/Base/post-base lookup.
public struct QPACKDynamicTable: Sendable, Equatable {
    /// Entries newest-first: `entries[0]` is the most recently inserted (absolute index `insertCount-1`).
    private var entries: [HeaderField] = []

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

    /// The number of entries currently held (insertCount minus evicted).
    public var count: Int { entries.count }

    /// Whether the table currently holds no entries.
    public var isEmpty: Bool { entries.isEmpty }

    /// The absolute index of the oldest still-present entry (RFC 9204 §3.2.4); equals `insertCount`
    /// when the table is empty (no entry is addressable).
    public var oldestAbsoluteIndex: Int { insertCount - entries.count }

    /// Returns the entry at *absolute* index `absolute` (RFC 9204 §3.2.4), or nil if it was never
    /// inserted or has been evicted.
    public func field(atAbsolute absolute: Int) -> HeaderField? {
        // entries[position] has absolute index `insertCount - 1 - position` (newest-first).
        let position = insertCount - 1 - absolute
        guard position >= 0, position < entries.count else {
            return nil
        }
        return entries[position]
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

    /// Inserts `field` as the newest entry, first evicting the oldest entries to make room (§3.2.2).
    ///
    /// Returns false without inserting if `field` is larger than the whole capacity — a §3.2.2 error the
    /// caller maps to QPACK_ENCODER_STREAM_ERROR (the table is left unchanged, not emptied as in HPACK).
    @discardableResult
    public mutating func insert(_ field: HeaderField) -> Bool {
        guard field.tableSize <= capacity else {
            return false
        }
        evict(untilRoomFor: field.tableSize)
        entries.insert(field, at: 0)
        size += field.tableSize
        insertCount += 1
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

    /// Evicts the oldest entries until `incoming` more octets would fit within ``capacity`` (§3.2.2).
    ///
    /// Eviction removes the entry with the *lowest* absolute index; `insertCount` is unchanged, so every
    /// surviving entry keeps its absolute index (the §3.2.4 invariant the lookups above rely on).
    private mutating func evict(untilRoomFor incoming: Int) {
        while !entries.isEmpty, size + incoming > capacity {
            size -= entries.removeLast().tableSize
        }
    }
}
