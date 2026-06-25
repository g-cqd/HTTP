//
//  QPACKEncoder+Dynamic.swift
//  QPACK
//
//  RFC 9204 §4.3 / §4.5 — the encoder's dynamic-table path. The strategy is deliberately conservative so
//  it is provably interoperable and never corrupts a peer's decode:
//
//    * never evict — a field is inserted only while the table has room (§2.1.3 is then trivial: no
//      entry a pending, unacknowledged section references is ever displaced);
//    * never block — a dynamic entry is referenced only once the peer's Insert Count Increment confirms
//      it received that insert (`absolute < knownReceivedCount`), so a section's Required Insert Count
//      never exceeds what the peer holds and the peer never waits (§2.1.2);
//    * insert on second use — a field is inserted only after it recurs, so unique per-response values
//      (date, etag, content-length) never crowd out genuinely repeated ones.
//
//  Because every reference is to a known-received entry, Base is fixed at the known-received count and
//  the §4.5.1.2 prefix is always the S=0 form. The peer applies the inserts off the §4.3 encoder stream;
//  this section then resolves them. A peer that disables the table leaves the encoder on the static path.
//

public import HTTPCore

extension QPACKEncoder {
    /// Encodes `fields` into a field section plus the encoder-stream instructions its inserts require
    /// (RFC 9204 §4.3 / §4.5).
    ///
    /// Returns the field-section bytes (for the request/response stream) and the encoder-stream bytes
    /// (Set Capacity + inserts, for the QPACK encoder stream). The encoder-stream bytes are empty when no
    /// insert is made; the section is byte-identical to the static path when nothing dynamic is
    /// referenced (Required Insert Count 0).
    public mutating func encodeSection(
        _ fields: [HeaderField]
    ) -> (section: [UInt8], encoderStream: [UInt8]) {
        var encoderStream: [UInt8] = []
        if let capacity = pendingCapacity {
            encoderStream += QPACKInstructions.setDynamicTableCapacity(capacity)
            pendingCapacity = nil
        }
        for field in fields {
            considerInsert(field, into: &encoderStream)
        }
        let base = knownReceivedCount
        var representations: [UInt8] = []
        representations.reserveCapacity(
            fields.reduce(0) { $0 + $1.name.utf8.count + $1.value.utf8.count + 2 }
        )
        var maxAbsolute = -1
        for field in fields {
            encodeFieldDynamic(field, base: base, into: &representations, maxAbsolute: &maxAbsolute)
        }
        var section: [UInt8] = []
        section.reserveCapacity(representations.count + 2)
        appendPrefix(requiredInsertCount: maxAbsolute + 1, base: base, into: &section)
        section += representations
        return (section, encoderStream)
    }

    /// Inserts `field` into the dynamic table when it recurs and still fits without eviction, emitting the
    /// §4.3.2/§4.3.3 instruction; otherwise leaves the table unchanged.
    private mutating func considerInsert(_ field: HeaderField, into encoderStream: inout [UInt8]) {
        // Already representable as a static-exact match or an existing dynamic entry → no insert needed.
        guard QPACKStaticTable.exactIndex[field] == nil,
            table.absoluteIndex(of: field) == nil
        else {
            return
        }
        // Insert only a field proven to repeat that still fits without evicting a referenced entry.
        guard recordAndCheckRepeat(field), table.hasRoom(for: field) else {
            return
        }
        let value = Array(field.value.utf8)
        if let nameIndex = QPACKStaticTable.nameIndex[field.name] {
            encoderStream += QPACKInstructions.insertWithStaticName(index: nameIndex, value: value)
        }
        else {
            let name = Array(field.name.utf8)
            encoderStream += QPACKInstructions.insertWithLiteralName(name: name, value: value)
        }
        table.insert(field)
    }

    /// Records `field` as seen and reports whether it had already been seen (a repeat worth inserting).
    ///
    /// A repeat is removed from the window — it is about to live in the dynamic table — while a first
    /// sighting is appended, evicting the oldest tracked field past ``recentFieldLimit``.
    private mutating func recordAndCheckRepeat(_ field: HeaderField) -> Bool {
        if let position = recentFields.firstIndex(of: field) {
            recentFields.remove(at: position)
            return true
        }
        recentFields.append(field)
        if recentFields.count > recentFieldLimit {
            recentFields.removeFirst()
        }
        return false
    }

    /// Encodes one field line, preferring a known-received dynamic indexed reference (§4.5.2) over the
    /// static path, and raising `maxAbsolute` to the highest dynamic absolute index it references.
    private func encodeFieldDynamic(
        _ field: HeaderField, base: Int, into reps: inout [UInt8], maxAbsolute: inout Int
    ) {
        if let absolute = dynamicReference(for: field) {
            // §4.5.2 — a dynamic indexed field line (T=0), relative to Base = knownReceivedCount.
            QPACKInteger.encode(base - 1 - absolute, prefixBits: 6, firstByte: 0x80, into: &reps)
            maxAbsolute = max(maxAbsolute, absolute)
            return
        }
        encode(field, into: &reps)  // §4.5 static-exact / static-name / literal
    }

    /// The absolute index of a known-received dynamic entry equal to `field` that the static table does
    /// not already cover exactly, or nil (RFC 9204 §4.5.2) — referencing only known-received entries is
    /// what keeps a section from ever blocking the peer.
    private func dynamicReference(for field: HeaderField) -> Int? {
        guard QPACKStaticTable.exactIndex[field] == nil else {
            return nil  // a static-exact field uses the cheaper static representation
        }
        guard let absolute = table.absoluteIndex(of: field), absolute < knownReceivedCount else {
            return nil  // absent, or inserted but not yet acknowledged as received
        }
        return absolute
    }

    /// Writes the §4.5.1 prefix for `requiredInsertCount` and `base`.
    ///
    /// A zero Required Insert Count is the static prefix (RIC 0, Base 0). Otherwise `base ≥ ric` always
    /// holds — references are to known-received entries, so `ric ≤ knownReceivedCount = base` — giving
    /// the S=0 form with DeltaBase = base − ric (§4.5.1.2); the wrapped Encoded Insert Count uses the
    /// same MaxEntries = capacity / 32 the peer decoder applies (§4.5.1.1).
    private func appendPrefix(requiredInsertCount ric: Int, base: Int, into output: inout [UInt8]) {
        guard ric > 0 else {
            output.append(0x00)  // Required Insert Count 0
            output.append(0x00)  // S=0, Base 0
            return
        }
        let maxEntries = table.capacity / 32
        let encodedInsertCount = (ric % (2 * maxEntries)) + 1
        QPACKInteger.encode(encodedInsertCount, prefixBits: 8, into: &output)
        QPACKInteger.encode(base - ric, prefixBits: 7, firstByte: 0x00, into: &output)  // S=0
    }
}
