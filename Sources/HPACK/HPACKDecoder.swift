//
//  HPACKDecoder.swift
//  HPACK
//
//  RFC 7541 §6 — the HPACK decoder. It walks a header block one representation at a time (iterative,
//  no recursion), resolving the four field representations and the dynamic table size update against
//  the combined index address space, and mutating the dynamic table as §6.2.1 / §6.3 require. The
//  decoder is stateful: one instance per connection-direction, since the dynamic table carries across
//  header blocks.
//

public import HTTPCore

/// A stateful HPACK decoder (RFC 7541 §6); the dynamic table persists across header blocks.
public struct HPACKDecoder {

    /// The dynamic table, shared across every block this decoder processes.
    public private(set) var dynamicTable: HPACKDynamicTable

    /// The protocol-negotiated upper bound for a dynamic table size update (RFC 7541 §6.3).
    private let maxDynamicTableSize: Int

    private let limits: HTTPLimits

    /// Creates a decoder whose dynamic table starts at `maxDynamicTableSize` octets.
    public init(maxDynamicTableSize: Int, limits: HTTPLimits = .default) {
        self.dynamicTable = HPACKDynamicTable(maxSize: maxDynamicTableSize)
        self.maxDynamicTableSize = maxDynamicTableSize
        self.limits = limits
    }

    /// Decodes a complete header block into its fields (RFC 7541 §6).
    ///
    /// Bounds the cumulative decoded list against ``HTTPLimits/maxHeaderListSize`` (a decompression-
    /// bomb defense) and fails closed on any malformed representation.
    public mutating func decode(_ block: RawSpan) throws(HPACKError) -> [HPACKField] {
        var reader = ByteReader(block)
        var fields = [HPACKField]()
        var decodedSize = 0
        while let first = reader.peek() {
            if first & 0x80 != 0 {
                fields.append(try decodeIndexed(&reader))
            } else if first & 0x40 != 0 {
                fields.append(try decodeLiteral(&reader, prefixBits: 6, addToTable: true))
            } else if first & 0x20 != 0 {
                // A dynamic table size update MUST precede any field in the block (RFC 7541 §4.2).
                guard fields.isEmpty else { throw .invalidTableSizeUpdate }
                try decodeSizeUpdate(&reader)
                continue
            } else {
                fields.append(try decodeLiteral(&reader, prefixBits: 4, addToTable: false))
            }
            // Bound the running decoded list size before accepting the field (§4.1 sizing).
            if let field = fields.last { decodedSize += field.tableSize }
            guard decodedSize <= limits.maxHeaderListSize else { throw .headerListTooLarge }
            // Bound the field *count* too: a swarm of tiny indexed references / Cookie crumbs
            // (RFC 9113 §8.2.3) can stay under the byte budget yet exhaust per-field allocation —
            // the header-count bomb (CVE-2016-6581 class). The byte limit alone misses it.
            guard fields.count <= limits.maxFieldCount else { throw .tooManyFields }
        }
        return fields
    }

    /// RFC 7541 §6.1 — an indexed header field: the whole field comes from the table.
    private func decodeIndexed(_ reader: inout ByteReader) throws(HPACKError) -> HPACKField {
        let index = try HPACKInteger.decode(&reader, prefixBits: 7)
        guard index != 0, let field = dynamicTable.field(at: index) else { throw .invalidIndex }
        return field
    }

    /// RFC 7541 §6.2 — a literal header field; `addToTable` distinguishes §6.2.1 from §6.2.2 / §6.2.3.
    ///
    /// A non-zero name index references the table; a zero index means the name is itself a literal.
    private mutating func decodeLiteral(
        _ reader: inout ByteReader,
        prefixBits: Int,
        addToTable: Bool
    ) throws(HPACKError) -> HPACKField {
        let nameIndex = try HPACKInteger.decode(&reader, prefixBits: prefixBits)
        let name: String
        if nameIndex == 0 {
            name = try HPACKString.decodeString(&reader, maxEncodedLength: limits.maxFieldSize)
        } else {
            guard let entry = dynamicTable.field(at: nameIndex) else { throw .invalidIndex }
            name = entry.name
        }
        let value = try HPACKString.decodeString(&reader, maxEncodedLength: limits.maxFieldSize)
        let field = HPACKField(name: name, value: value)
        if addToTable { dynamicTable.add(field) }
        return field
    }

    /// RFC 7541 §6.3 — a dynamic table size update, capped at the protocol-negotiated maximum.
    private mutating func decodeSizeUpdate(_ reader: inout ByteReader) throws(HPACKError) {
        let newSize = try HPACKInteger.decode(&reader, prefixBits: 5)
        guard newSize <= maxDynamicTableSize else { throw .invalidTableSizeUpdate }
        dynamicTable.setMaxSize(newSize)
    }
}
