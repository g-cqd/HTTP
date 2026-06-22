//
//  QPACKDecoder.swift
//  QPACK
//
//  RFC 9204 §4.5 — the QPACK field-section decoder. It reads the §4.5.1 encoded field-section prefix
//  (Required Insert Count + Delta Base) and then each field-line representation (§4.5.2–§4.5.6),
//  iteratively (no recursion). The dynamic table is disabled in v1 (SETTINGS_QPACK_MAX_TABLE_CAPACITY
//  = 0, RFC 9204 §3.2.2): the Required Insert Count MUST be 0 and the Base MUST be 0, and every
//  dynamic-table representation (indexed/literal name reference with T=0, and the post-base forms) is a
//  decoding failure. Only static-table references and literals are accepted. Any fault is a
//  QPACK_DECOMPRESSION_FAILED (RFC 9204 §6).
//
//  The HPACK decompression-bomb guards are carried over: the cumulative decoded list is bounded by
//  `maxHeaderListSize`, the field count by `maxFieldCount`, and each string by `maxFieldSize`.
//

public import HTTPCore

/// A QPACK field-section decoder with the dynamic table disabled (RFC 9204 §4.5, capacity 0).
public struct QPACKDecoder {

    private let limits: HTTPLimits

    /// Creates a decoder enforcing `limits` (the decompression-bomb bounds).
    public init(limits: HTTPLimits = .default) {
        self.limits = limits
    }

    /// Decodes a complete encoded field section into its fields (RFC 9204 §4.5).
    ///
    /// Fails closed with `QPACK_DECOMPRESSION_FAILED` on any malformed representation, any
    /// dynamic-table reference (the table is disabled), or a breach of the decompression bounds.
    public func decode(_ block: RawSpan) throws(QPACKError) -> [HeaderField] {
        var reader = ByteReader(block)
        try decodePrefix(&reader)
        var fields = [HeaderField]()
        var decodedSize = 0
        while let first = reader.peek() {
            let field = try decodeRepresentation(&reader, first: first)
            // Bound the running decoded list by §3.2.1 entry sizing (a decompression-bomb defense).
            decodedSize += field.tableSize
            guard decodedSize <= limits.maxHeaderListSize else {
                throw .decompressionFailed("header list too large")
            }
            fields.append(field)
            guard fields.count <= limits.maxFieldCount else {
                throw .decompressionFailed("too many fields")
            }
        }
        return fields
    }

    /// Reads the §4.5.1 encoded field-section prefix, requiring Required Insert Count 0 and Base 0.
    ///
    /// With the dynamic table disabled, a field section may not depend on inserts: a non-zero Required
    /// Insert Count is a reference beyond the (zero) blocked-streams limit, and a non-zero Base
    /// references absent dynamic entries — both are decoding failures (RFC 9204 §2.1.1 / §4.5.1).
    private func decodePrefix(_ reader: inout ByteReader) throws(QPACKError) {
        switch QPACKInteger.decode(&reader, prefixBits: 8) {
        case .value(0):
            break  // Required Insert Count 0 — static-table-only, as required at capacity 0
        case .value:
            throw .decompressionFailed("non-zero Required Insert Count requires the dynamic table")
        case .incomplete, .overflow:
            throw .decompressionFailed("invalid Required Insert Count")
        }
        guard let signByte = reader.peek() else { throw .decompressionFailed("truncated Base") }
        let signNegative = signByte & 0x80 != 0
        switch QPACKInteger.decode(&reader, prefixBits: 7) {
        case .value(0) where !signNegative:
            break  // Base 0
        case .value:
            throw .decompressionFailed("non-zero Base requires the dynamic table")
        case .incomplete, .overflow:
            throw .decompressionFailed("invalid Base")
        }
    }

    /// Dispatches one field-line representation by its leading bits (RFC 9204 §4.5.2–§4.5.6).
    private func decodeRepresentation(
        _ reader: inout ByteReader, first: UInt8
    ) throws(QPACKError) -> HeaderField {
        if first & 0x80 != 0 {
            return try decodeIndexed(&reader, first: first)  // §4.5.2: 1Txxxxxx
        } else if first & 0x40 != 0 {
            return try decodeLiteralWithNameReference(&reader, first: first)  // §4.5.4: 01NTxxxx
        } else if first & 0x20 != 0 {
            return try decodeLiteralWithLiteralName(&reader)  // §4.5.6: 001NHxxx
        }
        // §4.5.3 post-base indexed (0001) and §4.5.5 post-base name reference (0000) both reference
        // the dynamic table, which is disabled — no valid representation can use them.
        throw .decompressionFailed("post-base representation requires the dynamic table")
    }

    /// RFC 9204 §4.5.2 — an indexed field line; only a static reference (T=1) is valid at capacity 0.
    private func decodeIndexed(
        _ reader: inout ByteReader, first: UInt8
    ) throws(QPACKError) -> HeaderField {
        guard first & 0x40 != 0 else {
            throw .decompressionFailed("dynamic-table reference (capacity 0)")
        }
        let index = try integer(&reader, prefixBits: 6, what: "index")
        guard let field = QPACKStaticTable.field(at: index) else {
            throw .decompressionFailed("invalid static-table index")
        }
        return field
    }

    /// RFC 9204 §4.5.4 — a literal field line with a static name reference (T=1) and a literal value.
    private func decodeLiteralWithNameReference(
        _ reader: inout ByteReader, first: UInt8
    ) throws(QPACKError) -> HeaderField {
        guard first & 0x10 != 0 else {
            throw .decompressionFailed("dynamic-table name reference (capacity 0)")
        }
        let nameIndex = try integer(&reader, prefixBits: 4, what: "name index")
        guard let entry = QPACKStaticTable.field(at: nameIndex) else {
            throw .decompressionFailed("invalid static-table name index")
        }
        let value = try QPACKString.decodeString(
            &reader, prefixBits: 7, maxEncodedLength: limits.maxFieldSize)
        return HeaderField(name: entry.name, value: value)
    }

    /// RFC 9204 §4.5.6 — a literal field line with a literal name (3-bit name length) and value.
    private func decodeLiteralWithLiteralName(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> HeaderField {
        let name = try QPACKString.decodeString(
            &reader, prefixBits: 3, maxEncodedLength: limits.maxFieldSize)
        let value = try QPACKString.decodeString(
            &reader, prefixBits: 7, maxEncodedLength: limits.maxFieldSize)
        return HeaderField(name: name, value: value)
    }

    /// Decodes a prefix integer, mapping truncation/overflow to a decoding failure (RFC 9204 §6).
    private func integer(
        _ reader: inout ByteReader, prefixBits: Int, what: String
    ) throws(QPACKError) -> Int {
        switch QPACKInteger.decode(&reader, prefixBits: prefixBits) {
        case .value(let value): return value
        case .incomplete, .overflow: throw .decompressionFailed("invalid \(what)")
        }
    }
}
