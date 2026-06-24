//
//  HPACKDynamicTable.swift
//  HPACK
//
//  RFC 7541 §2.3.2 / §4 — the HPACK dynamic table: a FIFO of recently inserted fields that, together
//  with the static table, forms one index address space (§2.3.3). Indices 1...61 are static; 62 and
//  up are dynamic with 62 addressing the most recently inserted entry. Insertion evicts the oldest
//  entries to honor the size bound (§4.4), and an entry larger than the whole table empties it.
//

public import HTTPCore

/// The RFC 7541 §2.3.2 dynamic table (with the combined §2.3.3 index lookup).
public struct HPACKDynamicTable: Sendable, Equatable {
    /// Entries newest-first: `entries[0]` is the most recently added (HPACK index 62).
    private var entries: [HPACKField] = []

    /// The current table size in octets (sum of entry sizes, RFC 7541 §4.1).
    public private(set) var size = 0

    /// The maximum table size in octets (RFC 7541 §4.2); changed via ``setMaxSize(_:)``.
    public private(set) var maxSize: Int

    /// Creates an empty dynamic table bounded by `maxSize` octets.
    public init(maxSize: Int) {
        self.maxSize = maxSize
    }

    /// The number of entries currently held.
    public var count: Int { entries.count }

    /// Returns the field at combined HPACK index `index`, or `nil` if it addresses no entry.
    ///
    /// `1...61` index the static table; `62...` index the dynamic table, newest first (§2.3.3).
    public func field(at index: Int) -> HPACKField? {
        if let staticField = HPACKStaticTable.field(at: index) { return staticField }
        let position = index - HPACKStaticTable.count - 1
        guard position >= 0, position < entries.count else { return nil }
        return entries[position]
    }

    /// Returns the combined HPACK index of the first entry satisfying `matches`, newest-first, or nil.
    ///
    /// Used by the encoder to find a usable dynamic-table reference (RFC 7541 §2.3.3 numbering).
    public func firstIndex(where matches: (HPACKField) -> Bool) -> Int? {
        for (position, field) in entries.enumerated() where matches(field) {
            return HPACKStaticTable.count + 1 + position
        }
        return nil
    }

    /// Inserts `field` as the newest entry, first evicting the oldest entries to make room (§4.4).
    ///
    /// If `field` is larger than the entire table, the table is emptied and nothing is inserted —
    /// not an error, per §4.4.
    public mutating func add(_ field: HPACKField) {
        evict(untilRoomFor: field.tableSize)
        guard field.tableSize <= maxSize else { return }
        entries.insert(field, at: 0)
        size += field.tableSize
    }

    /// Sets a new maximum size, evicting the oldest entries until the table fits (RFC 7541 §6.3).
    public mutating func setMaxSize(_ newMaxSize: Int) {
        maxSize = newMaxSize
        evict(untilRoomFor: 0)
    }

    /// Evicts the oldest entries until `incoming` more octets would fit within ``maxSize``.
    private mutating func evict(untilRoomFor incoming: Int) {
        while !entries.isEmpty, size + incoming > maxSize {
            size -= entries.removeLast().tableSize
        }
    }
}
