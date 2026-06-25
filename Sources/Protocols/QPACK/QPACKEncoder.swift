//
//  QPACKEncoder.swift
//  QPACK
//
//  RFC 9204 §4.5 — the QPACK field-section encoder. With the dynamic table disabled (the default) it
//  picks the most compact static representation per field: an Indexed Field Line (§4.5.2) when the whole
//  name/value pair is in the static table, a Literal Field Line with a static Name Reference (§4.5.4)
//  when only the name matches, or a Literal Field Line with a Literal Name (§4.5.6) otherwise — every
//  section is self-contained with a Required Insert Count 0, Base 0 prefix (§4.5.1).
//
//  When a peer advertises a dynamic-table capacity, ``enableDynamicTable(capacity:blockedStreams:)``
//  switches on the §4.3 encoder-stream path (``encodeSection(_:streamID:)`` in QPACKEncoder+Dynamic): the
//  full RFC 9204 strategy — it inserts a repeated field and references it immediately (the peer blocks
//  briefly, bounded by `SETTINGS_QPACK_BLOCKED_STREAMS`, §2.1.2), and evicts the oldest *unreferenced*
//  entries to admit new ones, tracking per-section references so it never evicts an entry an unacknowledged
//  section still needs (§2.1.3). The static path stays the fallback for a peer that disables the table,
//  and for the per-field streaming entry points below.
//

public import HTTPCore

/// A QPACK field-section encoder (RFC 9204 §4.5) — static-only until the dynamic table is enabled.
public struct QPACKEncoder {
    /// One unacknowledged field section: its Required Insert Count and the absolute indices it referenced,
    /// so a Section Acknowledgment / Stream Cancellation can release exactly those references (§2.1.3).
    struct OutstandingSection: Sendable {
        let requiredInsertCount: Int
        let references: [Int]
    }

    /// The encoder's view of its dynamic table (RFC 9204 §3.2); capacity 0 means static-only.
    var table = QPACKDynamicTable(capacity: 0)
    /// Inserts the peer's decoder has confirmed received (RFC 9204 §2.1.4, via Insert Count Increment);
    /// referencing only known-received or freshly-inserted entries keeps a section decodable.
    var knownReceivedCount = 0
    /// A Set Dynamic Table Capacity (§4.3.1) owed on the next section, after enabling the table.
    var pendingCapacity: Int?
    /// Recently seen not-yet-inserted fields, for the insert-on-second-use heuristic (bounded memory).
    var recentFields: [HeaderField] = []
    /// The cap on ``recentFields`` — a field must recur within this window to be inserted.
    let recentFieldLimit = 64
    /// How many entries reference each live absolute index across all unacknowledged sections — an entry
    /// with a non-zero count MUST NOT be evicted (RFC 9204 §2.1.3).
    var referenceCounts: [Int: Int] = [:]
    /// Per-stream FIFO of unacknowledged sections; Section Acknowledgment retires the oldest (§4.4.1).
    var outstandingSections: [UInt64: [OutstandingSection]] = [:]
    /// The peer's `SETTINGS_QPACK_BLOCKED_STREAMS` — the cap on streams that may be blocked at once
    /// (RFC 9204 §2.1.2); 0 disables blocking (the encoder then references only known-received entries).
    var peerBlockedStreams = 0

    /// Creates a static-only encoder.
    public init() {
        // The static-only encoder holds no live dynamic-table state (capacity 0).
    }

    /// Whether the dynamic table is enabled (the peer advertised a non-zero capacity).
    public var dynamicTableEnabled: Bool { table.capacity > 0 }

    /// Enables the dynamic table at `capacity` octets and permits up to `blockedStreams` blocked streams,
    /// owing a Set Capacity instruction on the next section (RFC 9204 §4.3.1 / §2.1.2).
    ///
    /// `capacity` is the minimum of the peer's advertised maximum and our own bound; 0 leaves the encoder
    /// static-only. `blockedStreams` is the peer's advertised `SETTINGS_QPACK_BLOCKED_STREAMS`.
    public mutating func enableDynamicTable(capacity: Int, blockedStreams: Int = 0) {
        guard capacity > 0 else {
            return
        }
        table.setCapacity(capacity)
        pendingCapacity = capacity
        peerBlockedStreams = max(0, blockedStreams)
    }

    /// Advances the known-received insert count by `count` (RFC 9204 §2.1.4 / §4.4.3 Insert Count
    /// Increment), so the encoder may now reference those entries without the peer blocking.
    public mutating func acknowledgeInserts(_ count: Int) {
        knownReceivedCount = min(knownReceivedCount + count, table.insertCount)
    }

    /// Encodes `fields` into a complete static-only encoded field section (RFC 9204 §4.5).
    ///
    /// The output begins with the §4.5.1 prefix (Required Insert Count 0, Base 0) and uses only
    /// static-table references and literals. For dynamic-table encoding use ``encodeSection(_:)``.
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
