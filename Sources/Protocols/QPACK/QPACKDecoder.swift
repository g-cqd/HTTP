//
//  QPACKDecoder.swift
//  QPACK
//
//  RFC 9204 §4.5 — the QPACK field-section decoder. It reads the §4.5.1 encoded field-section prefix
//  (Required Insert Count + Delta Base) and then each field-line representation (§4.5.2–§4.5.6),
//  iteratively (no recursion).
//
//  Two modes share this type. With the dynamic table disabled (`maxTableCapacity == 0`, RFC 9204
//  §3.2.2) it is static-only: the Required Insert Count and Base MUST be 0 and every dynamic-table
//  representation is a decoding failure. With a non-zero capacity it tracks the entries the peer's
//  encoder inserts (``applyEncoderInstructions(_:)``, in +Dynamic) and resolves the §4.5.1 RIC/Base
//  arithmetic and the dynamic indexed / name-reference / post-base representations against the dynamic
//  table. Any fault is a QPACK_DECOMPRESSION_FAILED (RFC 9204 §6).
//
//  The HPACK decompression-bomb guards are carried over: the cumulative decoded list is bounded by
//  `maxHeaderListSize`, the field count by `maxFieldCount`, and each string by `maxFieldSize`.
//

public import HTTPCore

/// A QPACK field-section decoder (RFC 9204 §4.5) — static-only at capacity 0, dynamic above it.
public struct QPACKDecoder {
    let limits: HTTPLimits
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` we advertised (RFC 9204 §3.2.3); 0 disables the dynamic table.
    let maxTableCapacity: Int
    /// The dynamic table the peer's encoder populates (empty and unused at capacity 0).
    var table: QPACKDynamicTable

    /// Creates a static-only decoder (dynamic table disabled, RFC 9204 §3.2.2).
    public init(limits: HTTPLimits = .default) {
        self.init(maxTableCapacity: 0, limits: limits)
    }

    /// Creates a decoder advertising `maxTableCapacity` octets of dynamic table (RFC 9204 §3.2.3).
    ///
    /// At capacity 0 it is static-only; above it, ``applyEncoderInstructions(_:)`` populates the table
    /// and field sections may reference it.
    public init(maxTableCapacity: Int, limits: HTTPLimits = .default) {
        self.limits = limits
        self.maxTableCapacity = maxTableCapacity
        self.table = QPACKDynamicTable(capacity: maxTableCapacity)
    }

    /// The number of entries the peer has inserted so far (RFC 9204 §3.2.4) — the decoder's view of the
    /// insert count, which a Required Insert Count may not exceed.
    public var insertCount: Int { table.insertCount }

    /// Decodes a complete encoded field section into its fields (RFC 9204 §4.5).
    ///
    /// Fails closed with `QPACK_DECOMPRESSION_FAILED` on any malformed representation, a Required Insert
    /// Count past the entries received (the caller buffers a blocked section), or a breach of the
    /// decompression bounds.
    public func decode(_ block: RawSpan) throws(QPACKError) -> [HeaderField] {
        var reader = ByteReader(block)
        let prefix = try decodePrefix(&reader)
        guard prefix.requiredInsertCount <= table.insertCount else {
            throw .decompressionFailed("Required Insert Count exceeds the entries received")
        }
        var fields: [HeaderField] = []
        var decodedSize = 0
        while let first = reader.peek() {
            let field = try decodeRepresentation(&reader, first: first, base: prefix.base)
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

    /// Reads the §4.5.1 encoded field-section prefix, returning the resolved Required Insert Count/Base.
    ///
    /// At capacity 0 both MUST be 0 — a dynamic dependency references the absent table, a decoding
    /// failure (RFC 9204 §3.2.2).
    private func decodePrefix(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> (requiredInsertCount: Int, base: Int) {
        let encodedInsertCount: Int
        switch QPACKInteger.decode(&reader, prefixBits: 8) {
            case .value(let value):
                encodedInsertCount = value
            case .incomplete, .overflow:
                throw .decompressionFailed("invalid Required Insert Count")
        }
        guard let signByte = reader.peek() else { throw .decompressionFailed("truncated Base") }
        let signNegative = signByte & 0x80 != 0
        let deltaBase: Int
        switch QPACKInteger.decode(&reader, prefixBits: 7) {
            case .value(let value):
                deltaBase = value
            case .incomplete, .overflow:
                throw .decompressionFailed("invalid Base")
        }
        guard maxTableCapacity > 0 else {
            // Static-only (§3.2.2): a non-zero RIC or Base references the absent dynamic table.
            guard encodedInsertCount == 0 else {
                throw .decompressionFailed("non-zero Required Insert Count needs the dynamic table")
            }
            guard !signNegative, deltaBase == 0 else {
                throw .decompressionFailed("non-zero Base requires the dynamic table")
            }
            return (0, 0)
        }
        let requiredInsertCount = try decodeRequiredInsertCount(encodedInsertCount)
        // §4.5.1.2 — Base = RIC + DeltaBase (S=0) or RIC − DeltaBase − 1 (S=1, post-base addressing).
        let base =
            signNegative ? requiredInsertCount - deltaBase - 1 : requiredInsertCount + deltaBase
        guard base >= 0 else { throw .decompressionFailed("negative Base") }
        return (requiredInsertCount, base)
    }

    /// Reconstructs the Required Insert Count from its wrapped on-wire encoding (RFC 9204 §4.5.1.1).
    private func decodeRequiredInsertCount(_ encoded: Int) throws(QPACKError) -> Int {
        guard encoded != 0 else {
            return 0
        }
        let maxEntries = maxTableCapacity / 32
        guard maxEntries > 0 else {
            throw .decompressionFailed("dynamic reference with a zero-entry table")
        }
        let fullRange = 2 * maxEntries
        guard encoded <= fullRange else {
            throw .decompressionFailed("Required Insert Count out of range")
        }
        let maxValue = table.insertCount + maxEntries
        let maxWrapped = (maxValue / fullRange) * fullRange
        var requiredInsertCount = maxWrapped + encoded - 1
        if requiredInsertCount > maxValue {
            guard requiredInsertCount > fullRange else {
                throw .decompressionFailed("Required Insert Count overflow")
            }
            requiredInsertCount -= fullRange
        }
        return requiredInsertCount
    }

    /// Dispatches one field-line representation by its leading bits (RFC 9204 §4.5.2–§4.5.6).
    private func decodeRepresentation(
        _ reader: inout ByteReader, first: UInt8, base: Int
    ) throws(QPACKError) -> HeaderField {
        if first & 0x80 != 0 {
            return try decodeIndexed(&reader, first: first, base: base)  // §4.5.2: 1Txxxxxx
        }
        if first & 0x40 != 0 {
            return try decodeLiteralWithNameReference(&reader, first: first, base: base)  // §4.5.4
        }
        if first & 0x20 != 0 {
            return try decodeLiteralWithLiteralName(&reader)  // §4.5.6: 001NHxxx
        }
        if first & 0x10 != 0 {
            return try decodePostBaseIndexed(&reader, base: base)  // §4.5.3: 0001xxxx
        }
        return try decodeLiteralWithPostBaseNameReference(&reader, base: base)  // §4.5.5: 0000Nxxx
    }

    /// RFC 9204 §4.5.2 — an indexed field line: a static reference (T=1) or a Base-relative dynamic one.
    private func decodeIndexed(
        _ reader: inout ByteReader, first: UInt8, base: Int
    ) throws(QPACKError) -> HeaderField {
        let index = try integer(&reader, prefixBits: 6, what: "index")
        if first & 0x40 != 0 {
            guard let field = QPACKStaticTable.field(at: index) else {
                throw .decompressionFailed("invalid static-table index")
            }
            return field
        }
        guard let field = table.field(base: base, relativeIndex: index) else {
            throw .decompressionFailed("invalid dynamic-table index")
        }
        return field
    }

    /// RFC 9204 §4.5.4 — a literal field line with a static (T=1) or Base-relative dynamic name reference.
    private func decodeLiteralWithNameReference(
        _ reader: inout ByteReader, first: UInt8, base: Int
    ) throws(QPACKError) -> HeaderField {
        let nameIndex = try integer(&reader, prefixBits: 4, what: "name index")
        let name: String
        if first & 0x10 != 0 {
            guard let entry = QPACKStaticTable.field(at: nameIndex) else {
                throw .decompressionFailed("invalid static-table name index")
            }
            name = entry.name
        }
        else {
            guard let entry = table.field(base: base, relativeIndex: nameIndex) else {
                throw .decompressionFailed("invalid dynamic-table name index")
            }
            name = entry.name
        }
        let value = try QPACKString.decodeString(
            &reader, prefixBits: 7, maxEncodedLength: limits.maxFieldSize
        )
        return HeaderField(name: name, value: value)
    }

    /// RFC 9204 §4.5.6 — a literal field line with a literal name (3-bit name length) and value.
    private func decodeLiteralWithLiteralName(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> HeaderField {
        let name = try QPACKString.decodeString(
            &reader, prefixBits: 3, maxEncodedLength: limits.maxFieldSize
        )
        let value = try QPACKString.decodeString(
            &reader, prefixBits: 7, maxEncodedLength: limits.maxFieldSize
        )
        return HeaderField(name: name, value: value)
    }

    /// RFC 9204 §4.5.3 — a post-base indexed field line (absolute index `base + post-base index`).
    private func decodePostBaseIndexed(
        _ reader: inout ByteReader, base: Int
    ) throws(QPACKError) -> HeaderField {
        let index = try integer(&reader, prefixBits: 4, what: "post-base index")
        guard let field = table.field(base: base, postBaseIndex: index) else {
            throw .decompressionFailed("invalid post-base index")
        }
        return field
    }

    /// RFC 9204 §4.5.5 — a literal field line with a post-base dynamic name reference and a literal value.
    private func decodeLiteralWithPostBaseNameReference(
        _ reader: inout ByteReader, base: Int
    ) throws(QPACKError) -> HeaderField {
        let nameIndex = try integer(&reader, prefixBits: 3, what: "post-base name index")
        guard let entry = table.field(base: base, postBaseIndex: nameIndex) else {
            throw .decompressionFailed("invalid post-base name index")
        }
        let value = try QPACKString.decodeString(
            &reader, prefixBits: 7, maxEncodedLength: limits.maxFieldSize
        )
        return HeaderField(name: entry.name, value: value)
    }

    /// Decodes a prefix integer, mapping truncation/overflow to a decoding failure (RFC 9204 §6).
    func integer(
        _ reader: inout ByteReader, prefixBits: Int, what: String
    ) throws(QPACKError) -> Int {
        switch QPACKInteger.decode(&reader, prefixBits: prefixBits) {
            case .value(let value):
                return value
            case .incomplete, .overflow:
                throw .decompressionFailed("invalid \(what)")
        }
    }
}
