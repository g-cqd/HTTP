//
//  HPACKEncoder.swift
//  HPACK
//
//  RFC 7541 §6 — the HPACK encoder. For each field it prefers the most compact representation: an
//  indexed field (§6.1) when the whole name/value pair is already in a table, otherwise a literal
//  with incremental indexing (§6.2.1) — reusing a table name reference when possible and inserting
//  the field so later occurrences index it. Its dynamic table evolves in lock-step with a conformant
//  decoder's, so the two stay synchronized across a stream. Stateful: one per connection-direction.
//

public import HTTPCore

/// A stateful HPACK encoder (RFC 7541 §6); its dynamic table mirrors the peer decoder's.
public struct HPACKEncoder {
    /// The dynamic table, evolving in lock-step with the decoder across header blocks.
    public private(set) var dynamicTable: HPACKDynamicTable

    /// Creates an encoder whose dynamic table is bounded by `maxDynamicTableSize` octets.
    public init(maxDynamicTableSize: Int) {
        self.dynamicTable = HPACKDynamicTable(maxSize: maxDynamicTableSize)
    }

    /// Encodes `fields` into a single HPACK header block (RFC 7541 §6).
    public mutating func encode(_ fields: [HPACKField]) -> [UInt8] {
        var output: [UInt8] = []
        // Reserve once so the buffer does not realloc as fields append; the encoded form is ≤ name +
        // value + a couple octets per field (table refs + Huffman only shrink it).
        output.reserveCapacity(
            fields.reduce(0) { $0 + $1.name.utf8.count + $1.value.utf8.count + 2 }
        )
        for field in fields {
            encode(field, into: &output)
        }
        return output
    }

    /// Encodes one field into `output` (RFC 7541 §6.1 indexed, or §6.2.1 literal w/ incremental index).
    ///
    /// Mutates the dynamic table (a literal is inserted so later occurrences index it), so it stays in
    /// lock-step with the peer decoder. Call it directly to stream a block without a `[HPACKField]`.
    public mutating func encode(_ field: HPACKField, into output: inout [UInt8]) {
        if let index = exactIndex(of: field) {
            // §6.1 — the whole field is in a table: a single indexed reference.
            HPACKInteger.encode(index, prefixBits: 7, firstByte: 0x80, into: &output)
            return
        }
        // §6.2.1 — literal with incremental indexing, reusing a name reference when one exists.
        if let nameIndex = nameIndex(of: field.name) {
            HPACKInteger.encode(nameIndex, prefixBits: 6, firstByte: 0x40, into: &output)
        }
        else {
            HPACKInteger.encode(0, prefixBits: 6, firstByte: 0x40, into: &output)
            HPACKString.encode(field.name.utf8, into: &output)
        }
        HPACKString.encode(field.value.utf8, into: &output)
        dynamicTable.add(field)
    }

    /// The combined index of an exact `(name, value)` match (static first, then dynamic), or nil.
    private func exactIndex(of field: HPACKField) -> Int? {
        HPACKStaticTable.exactIndex[field] ?? dynamicTable.firstIndex { $0 == field }
    }

    /// The combined index of a name-only match (static first, then dynamic), or nil.
    private func nameIndex(of name: String) -> Int? {
        HPACKStaticTable.nameIndex[name] ?? dynamicTable.firstIndex { $0.name == name }
    }
}
