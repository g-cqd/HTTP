//
//  QPACKEncoder+Dynamic.swift
//  QPACK
//
//  RFC 9204 §4.3 / §4.5 — the encoder's dynamic-table path, the full RFC strategy. A repeated field is
//  inserted and referenced in the same section: the peer blocks until it reads the encoder stream, which
//  is allowed for up to `SETTINGS_QPACK_BLOCKED_STREAMS` streams at once (§2.1.2). To admit new entries
//  the encoder evicts the oldest entries — but only those with no outstanding reference, tracked per
//  section, so it never evicts an entry an unacknowledged section still needs (§2.1.3 / the §3.2.2 eviction
//  the peer mirrors). Base is fixed at the insert count, so every reference is a regular (pre-Base) index.
//
//  Insert-on-second-use keeps unique per-response values (date, etag, content-length) out of the table.
//  A field the static table already covers exactly is always encoded statically. A peer that disables the
//  table (capacity 0) leaves the encoder on the static path.
//

public import HTTPCore

extension QPACKEncoder {
    /// Encodes `fields` for `streamID` into a field section plus the encoder-stream instructions its
    /// inserts require (RFC 9204 §4.3 / §4.5).
    ///
    /// Returns the field-section bytes (for the request/response stream) and the encoder-stream bytes
    /// (Set Capacity + inserts, for the QPACK encoder stream). The section is byte-identical to the static
    /// path when nothing dynamic is referenced (Required Insert Count 0).
    public mutating func encodeSection(
        _ fields: [HeaderField], streamID: UInt64
    ) -> (section: [UInt8], encoderStream: [UInt8]) {
        var encoderStream: [UInt8] = []
        if let capacity = pendingCapacity {
            encoderStream += QPACKInstructions.setDynamicTableCapacity(capacity)
            pendingCapacity = nil
        }
        // Pass 1 — insert repeated fields (eviction-aware), building the encoder stream.
        for field in fields {
            considerInsert(field, into: &encoderStream)
        }
        // Pass 2 — encode representations against a now-fixed Base = insert count.
        let base = table.insertCount
        let mayBlock = mayBlockStream(streamID)
        var representations: [UInt8] = []
        representations.reserveCapacity(
            fields.reduce(0) { $0 + $1.name.utf8.count + $1.value.utf8.count + 2 }
        )
        var referenced: [Int] = []
        for field in fields {
            encodeFieldDynamic(
                field,
                base: base,
                mayBlock: mayBlock,
                into: &representations,
                referenced: &referenced
            )
        }
        let requiredInsertCount = (referenced.max() ?? -1) + 1
        var section: [UInt8] = []
        section.reserveCapacity(representations.count + 2)
        appendPrefix(requiredInsertCount: requiredInsertCount, base: base, into: &section)
        section += representations
        recordOutstanding(
            streamID: streamID,
            requiredInsertCount: requiredInsertCount,
            references: referenced
        )
        return (section, encoderStream)
    }

    // MARK: Insertion + eviction (RFC 9204 §3.2.2 / §2.1.3)

    /// Inserts `field` when it recurs and the table can make room by evicting only unreferenced entries,
    /// emitting the §4.3.2/§4.3.3 instruction; otherwise leaves the table unchanged.
    private mutating func considerInsert(_ field: HeaderField, into encoderStream: inout [UInt8]) {
        guard QPACKStaticTable.exactIndex[field] == nil,
            table.absoluteIndex(of: field) == nil
        else {
            return  // already representable as a static-exact match or an existing dynamic entry
        }
        // First sighting, or no room without evicting a still-referenced entry → leave it a candidate
        // (do not consume it from the window) so a later sighting can still insert it once room frees up.
        guard isRepeatedField(field), makeRoom(for: field) else {
            return
        }
        forgetRecentField(field)
        // Pass the `UTF8View`s straight to the instruction encoder (which takes `some Collection<UInt8>`)
        // — no `Array(field.*.utf8)` copy on the insert path.
        if let nameIndex = QPACKStaticTable.nameIndex[field.name] {
            encoderStream += QPACKInstructions.insertWithStaticName(
                index: nameIndex, value: field.value.utf8
            )
        }
        else {
            encoderStream += QPACKInstructions.insertWithLiteralName(
                name: field.name.utf8, value: field.value.utf8
            )
        }
        table.insert(field)  // room was ensured above, so this never evicts
    }

    /// Evicts the oldest *unreferenced* entries until `field` fits, returning whether it now fits.
    ///
    /// Works on a value copy so a partial eviction is never committed: if the oldest entry that still
    /// stands in the way is referenced by an unacknowledged section (RFC 9204 §2.1.3), nothing is evicted
    /// and the field is not inserted.
    private mutating func makeRoom(for field: HeaderField) -> Bool {
        guard field.tableSize <= table.capacity else {
            return false  // larger than the whole table — can never fit
        }
        var trial = table
        while !trial.hasRoom(for: field) {
            guard (referenceCounts[trial.oldestAbsoluteIndex] ?? 0) == 0 else {
                return false  // the oldest entry is still referenced — cannot make room
            }
            trial.evictOldest()
        }
        table = trial
        return true
    }

    /// Records `field` in the recent-sightings window and reports whether it had already been seen — a
    /// repeat worth inserting.
    ///
    /// The field stays in the window until it is actually inserted, so a repeat whose insert is deferred
    /// (no room yet) is not mistaken for a first sighting next time.
    private mutating func isRepeatedField(_ field: HeaderField) -> Bool {
        if recentFields.contains(field) {
            return true
        }
        recentFields.append(field)
        if recentFields.count > recentFieldLimit {
            recentFields.removeFirst()
        }
        return false
    }

    /// Drops `field` from the recent-sightings window once it lives in the dynamic table.
    private mutating func forgetRecentField(_ field: HeaderField) {
        if let position = recentFields.firstIndex(of: field) {
            recentFields.remove(at: position)
        }
    }

    // MARK: Representation + blocking (RFC 9204 §4.5 / §2.1.2)

    /// Encodes one field line, preferring a dynamic indexed reference (§4.5.2) over the static path and
    /// recording the absolute index it referenced.
    private func encodeFieldDynamic(
        _ field: HeaderField,
        base: Int,
        mayBlock: Bool,
        into reps: inout [UInt8],
        referenced: inout [Int]
    ) {
        if let absolute = referenceableDynamic(field, mayBlock: mayBlock) {
            QPACKInteger.encode(base - 1 - absolute, prefixBits: 6, firstByte: 0x80, into: &reps)
            referenced.append(absolute)
            return
        }
        encode(field, into: &reps)  // §4.5 static-exact / static-name / literal
    }

    /// The absolute index of a dynamic entry equal to `field` the encoder may reference: one the peer is
    /// known to hold, or — when `mayBlock` — a freshly inserted one the peer will block on briefly.
    private func referenceableDynamic(_ field: HeaderField, mayBlock: Bool) -> Int? {
        guard QPACKStaticTable.exactIndex[field] == nil else {
            return nil  // the static table covers it exactly — cheaper than a dynamic reference
        }
        guard let absolute = table.absoluteIndex(of: field) else {
            return nil
        }
        if absolute < knownReceivedCount {
            return absolute  // known-received — referencing it never blocks
        }
        return mayBlock ? absolute : nil
    }

    /// Whether a section on `streamID` may reference a not-yet-acknowledged entry — true if the stream is
    /// already blocked (no new blocked stream) or another blocked stream fits under the peer's limit.
    private func mayBlockStream(_ streamID: UInt64) -> Bool {
        if isStreamBlocked(streamID) {
            return true
        }
        return blockedStreamCount() < peerBlockedStreams
    }

    /// Whether `streamID` already has an unacknowledged section whose Required Insert Count exceeds the
    /// known-received count (RFC 9204 §2.1.2).
    private func isStreamBlocked(_ streamID: UInt64) -> Bool {
        guard let sections = outstandingSections[streamID] else {
            return false
        }
        return sections.contains { $0.requiredInsertCount > knownReceivedCount }
    }

    /// The number of streams currently blocked on not-yet-received inserts (RFC 9204 §2.1.2).
    private func blockedStreamCount() -> Int {
        outstandingSections.values.reduce(0) { count, sections in
            count + (sections.contains { $0.requiredInsertCount > knownReceivedCount } ? 1 : 0)
        }
    }

    /// Records a non-static section as outstanding and bumps the reference count of each entry it used,
    /// pinning those entries against eviction until the peer acknowledges the section (RFC 9204 §2.1.3).
    private mutating func recordOutstanding(
        streamID: UInt64, requiredInsertCount: Int, references: [Int]
    ) {
        guard requiredInsertCount > 0 else {
            return  // a Required-Insert-Count-0 section is never acknowledged (§4.4.1)
        }
        let section = OutstandingSection(
            requiredInsertCount: requiredInsertCount,
            references: references
        )
        outstandingSections[streamID, default: []].append(section)
        for absolute in references {
            referenceCounts[absolute, default: 0] += 1
        }
    }

    /// Writes the §4.5.1 prefix for `requiredInsertCount` and `base`.
    ///
    /// A zero Required Insert Count is the static prefix (RIC 0, Base 0). Otherwise `base ≥ ric` always
    /// holds — every reference is below the insert count — giving the S=0 form with DeltaBase = base − ric
    /// (§4.5.1.2); the wrapped Encoded Insert Count uses the MaxEntries = capacity / 32 the peer applies.
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
