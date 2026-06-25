//
//  QPACKDecoder+Dynamic.swift
//  QPACK
//
//  RFC 9204 §4.3 — applying the peer encoder's instruction stream to the decoder's dynamic table:
//  Set Dynamic Table Capacity (§4.3.1), Insert With Name Reference (§4.3.2), Insert With Literal Name
//  (§4.3.3), and Duplicate (§4.3.4). Parsing is incremental: a complete instruction is applied and its
//  octets consumed; a partial trailing instruction is left unconsumed (the reader at its start) so the
//  caller resumes when more bytes arrive. A malformed (not merely truncated) instruction is a
//  QPACK_ENCODER_STREAM_ERROR (RFC 9204 §6). The caller emits the returned insert count as a §4.4.3
//  Insert Count Increment on its decoder stream.
//

internal import HTTPCore

extension QPACKDecoder {
    /// Applies complete encoder-stream instructions to the dynamic table (RFC 9204 §4.3).
    ///
    /// Returns the octets consumed (a partial trailing instruction is left for the next call) and the
    /// number of new inserts applied — which the caller acknowledges as an Insert Count Increment.
    public mutating func applyEncoderInstructions(
        _ span: RawSpan
    ) throws(QPACKError) -> (consumed: Int, inserts: Int) {
        var reader = ByteReader(span)
        let startInserts = table.insertCount
        var committed = reader.position
        while let first = reader.peek() {
            guard try applyOneInstruction(&reader, first: first) else {
                break  // truncated — stop at the last complete instruction
            }
            committed = reader.position
        }
        return (committed, table.insertCount - startInserts)
    }

    /// Applies one instruction, advancing `reader` on success; returns false (reader unmoved) if
    /// truncated.
    private mutating func applyOneInstruction(
        _ reader: inout ByteReader, first: UInt8
    ) throws(QPACKError) -> Bool {
        if first & 0x80 != 0 {
            return try applyInsertWithNameReference(&reader, first: first)  // §4.3.2: 1Txxxxxx
        }
        if first & 0x40 != 0 {
            return try applyInsertWithLiteralName(&reader)  // §4.3.3: 01Hxxxxx
        }
        if first & 0x20 != 0 {
            return try applySetCapacity(&reader)  // §4.3.1: 001xxxxx
        }
        return try applyDuplicate(&reader)  // §4.3.4: 000xxxxx
    }

    /// RFC 9204 §4.3.2 — Insert With Name Reference: a static (T=1) or insert-point-relative dynamic
    /// name plus a literal value.
    private mutating func applyInsertWithNameReference(
        _ reader: inout ByteReader, first: UInt8
    ) throws(QPACKError) -> Bool {
        var probe = reader
        let index: Int
        switch QPACKInteger.decode(&probe, prefixBits: 6) {
            case .value(let value):
                index = value
            case .incomplete:
                return false
            case .overflow:
                throw .encoderStreamError("invalid insert name index")
        }
        guard let value = try completeString(&probe, prefixBits: 7) else {
            return false
        }
        let name = try insertName(static: first & 0x40 != 0, index: index)
        guard table.insert(HeaderField(name: name, value: value)) else {
            throw .encoderStreamError("inserted entry larger than the table capacity")
        }
        reader = probe
        return true
    }

    /// The name an Insert With Name Reference resolves — static table or the insert-point-relative
    /// dynamic entry (RFC 9204 §3.2.4).
    private func insertName(static isStatic: Bool, index: Int) throws(QPACKError) -> String {
        if isStatic {
            guard let entry = QPACKStaticTable.field(at: index) else {
                throw .encoderStreamError("invalid static-table name index")
            }
            return entry.name
        }
        guard let entry = table.field(relativeToInsertPoint: index) else {
            throw .encoderStreamError("invalid dynamic-table name index")
        }
        return entry.name
    }

    /// RFC 9204 §4.3.3 — Insert With Literal Name: a literal name (5-bit prefix) and literal value.
    private mutating func applyInsertWithLiteralName(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> Bool {
        var probe = reader
        guard let name = try completeString(&probe, prefixBits: 5),
            let value = try completeString(&probe, prefixBits: 7)
        else {
            return false
        }
        guard table.insert(HeaderField(name: name, value: value)) else {
            throw .encoderStreamError("inserted entry larger than the table capacity")
        }
        reader = probe
        return true
    }

    /// RFC 9204 §4.3.1 — Set Dynamic Table Capacity (≤ the advertised maximum).
    private mutating func applySetCapacity(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> Bool {
        var probe = reader
        let capacity: Int
        switch QPACKInteger.decode(&probe, prefixBits: 5) {
            case .value(let value):
                capacity = value
            case .incomplete:
                return false
            case .overflow:
                throw .encoderStreamError("invalid Set Dynamic Table Capacity")
        }
        guard capacity <= maxTableCapacity else {
            throw .encoderStreamError("Set Dynamic Table Capacity exceeds the limit")
        }
        table.setCapacity(capacity)
        reader = probe
        return true
    }

    /// RFC 9204 §4.3.4 — Duplicate an existing entry (insert-point-relative) to the insert point.
    private mutating func applyDuplicate(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> Bool {
        var probe = reader
        let index: Int
        switch QPACKInteger.decode(&probe, prefixBits: 5) {
            case .value(let value):
                index = value
            case .incomplete:
                return false
            case .overflow:
                throw .encoderStreamError("invalid Duplicate")
        }
        guard table.duplicate(relativeIndex: index) else {
            throw .encoderStreamError("Duplicate of an evicted or invalid index")
        }
        reader = probe
        return true
    }

    /// Decodes a string literal only when it has fully arrived (RFC 9204 §4.1.2): returns nil if the
    /// length integer is truncated or the payload has not all arrived, throwing on a malformed one.
    private func completeString(
        _ reader: inout ByteReader, prefixBits: Int
    ) throws(QPACKError) -> String? {
        guard let first = reader.peek() else {
            return nil
        }
        let huffman = (first >> UInt8(prefixBits)) & 1 == 1
        var probe = reader
        let length: Int
        switch QPACKInteger.decode(&probe, prefixBits: prefixBits) {
            case .value(let value):
                length = value
            case .incomplete:
                return nil
            case .overflow:
                throw .encoderStreamError("invalid string length")
        }
        guard length <= limits.maxFieldSize else {
            throw .encoderStreamError("inserted string too long")
        }
        guard probe.remaining >= length else {
            return nil  // the payload has not fully arrived
        }
        let start = probe.position
        probe.advance(by: length)
        let payload = probe.slice(in: start ..< (start + length))
        let string = try decodePayload(payload, huffman: huffman)
        reader = probe
        return string
    }

    /// Decodes the (possibly Huffman-coded) octets of a fully-present string (RFC 9204 §4.1.2).
    private func decodePayload(_ payload: RawSpan, huffman: Bool) throws(QPACKError) -> String {
        guard huffman else {
            return payload.withUnsafeBytes { String(decoding: $0, as: Unicode.UTF8.self) }
        }
        do {
            return try Huffman.decodeString(payload)
        }
        catch {
            throw .encoderStreamError("invalid Huffman in an inserted string")
        }
    }
}
