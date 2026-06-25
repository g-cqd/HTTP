//
//  QPACKEncoder.swift
//  QPACK
//
//  RFC 9204 §4.5 — the QPACK field-section encoder, dynamic table disabled (v1). For each field it
//  picks the most compact static representation: an Indexed Field Line (§4.5.2) when the whole
//  name/value pair is in the static table, a Literal Field Line with a static Name Reference (§4.5.4)
//  when only the name matches, or a Literal Field Line with a Literal Name (§4.5.6) otherwise. Because
//  the dynamic table is off, the encoder never inserts and never emits encoder-stream instructions —
//  every field section is self-contained, so the §4.5.1 prefix is always Required Insert Count 0,
//  Base 0. Its output decodes with a conformant decoder that requires RIC 0 (this module's decoder).
//

public import HTTPCore

/// A QPACK field-section encoder with the dynamic table disabled (RFC 9204 §4.5, capacity 0).
public struct QPACKEncoder {
    /// Creates a static-only encoder.
    public init() {
        // No-op: the static-only encoder holds no state.
    }

    /// Encodes `fields` into a complete encoded field section (RFC 9204 §4.5).
    ///
    /// The output begins with the §4.5.1 prefix (Required Insert Count 0, Base 0) and uses only
    /// static-table references and literals.
    public func encode(_ fields: [HeaderField]) -> [UInt8] {
        var output: [UInt8] = []
        // Reserve once for the whole section so the buffer never reallocs as fields append; the encoded
        // form is ≤ name + value + a couple octets per field (static refs + Huffman only shrink it).
        output.reserveCapacity(
            2 + fields.reduce(0) { $0 + $1.name.utf8.count + $1.value.utf8.count + 2 }
        )
        beginSection(into: &output)
        for field in fields {
            encode(field, into: &output)
        }
        return output
    }

    /// Writes the §4.5.1 field-section prefix (Required Insert Count 0, Base 0).
    ///
    /// Call once before encoding fields with ``encode(_:into:)`` to stream a section directly into a
    /// buffer, without first materializing a `[HeaderField]`.
    public func beginSection(into output: inout [UInt8]) {
        output.append(0x00)  // Required Insert Count 0
        output.append(0x00)  // Base sign bit 0 + Base 0
    }

    /// Encodes one field line into `output` (§4.5.2 indexed / §4.5.4 static name ref / §4.5.6 literal).
    public func encode(_ field: HeaderField, into output: inout [UInt8]) {
        if let index = QPACKStaticTable.exactIndex[field] {
            // §4.5.2 — the whole field is in the static table: an indexed reference (T=1).
            QPACKInteger.encode(index, prefixBits: 6, firstByte: 0xC0, into: &output)
            return
        }
        if let nameIndex = QPACKStaticTable.nameIndex[field.name] {
            // §4.5.4 — a static name reference (N=0, T=1 → 0x50) plus a literal value.
            QPACKInteger.encode(nameIndex, prefixBits: 4, firstByte: 0x50, into: &output)
            QPACKString.encode(field.value.utf8, prefixBits: 7, into: &output)
            return
        }
        // §4.5.6 — a literal name (N=0 → 0x20; the H flag is set by the string codec) plus a value.
        QPACKString.encode(field.name.utf8, prefixBits: 3, firstByte: 0x20, into: &output)
        QPACKString.encode(field.value.utf8, prefixBits: 7, into: &output)
    }
}
