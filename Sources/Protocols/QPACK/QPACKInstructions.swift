//
//  QPACKInstructions.swift
//  QPACK
//
//  RFC 9204 §4.3 (encoder stream) / §4.4 (decoder stream) — the QPACK instruction streams. With the
//  dynamic table disabled (capacity 0), this endpoint never inserts and every field section it sends
//  has Required Insert Count 0, so it owes NO instructions: the generators are stubs returning empty.
//  The parsers exist to *detect violations* a peer might commit, mapping each to its RFC 9204 §6 code:
//
//    Encoder stream (§4.3): a Set Dynamic Table Capacity above the negotiated limit, or any insert /
//      duplicate (the table is disabled, so nothing may be inserted) → QPACK_ENCODER_STREAM_ERROR.
//    Decoder stream (§4.4): an Insert Count Increment (we sent no inserts; an increment of 0 is invalid
//      regardless), or a Section Acknowledgment (our sections are all RIC 0) → QPACK_DECODER_STREAM_ERROR.
//      A Stream Cancellation carries no dynamic-table state for us and is consumed and ignored.
//
//  Parsing is incremental: a partial trailing instruction is left unconsumed (the reader is positioned
//  at its start) so the caller can resume when more bytes arrive.
//

public import HTTPCore

/// Parsers and generators for the QPACK encoder/decoder instruction streams (RFC 9204 §4.3/§4.4).
public enum QPACKInstructions {
    // MARK: Generators

    /// The unsolicited encoder-stream instructions owed when idle — always empty (RFC 9204 §4.3); the
    /// dynamic encoder emits its inserts per-section via the explicit generators below.
    public static func encoderStreamOutput() -> [UInt8] { [] }

    /// The unsolicited decoder-stream instructions owed when idle — always empty (RFC 9204 §4.4); the
    /// dynamic decoder emits Section Acknowledgment / Insert Count Increment via the generators below.
    public static func decoderStreamOutput() -> [UInt8] { [] }

    /// A Section Acknowledgment for `streamID` (RFC 9204 §4.4.1: `1` + a 7-bit prefix stream id) — sent
    /// once a field section that depended on the dynamic table has been decoded.
    public static func sectionAcknowledgment(streamID: UInt64) -> [UInt8] {
        var output: [UInt8] = []
        QPACKInteger.encode(Int(clamping: streamID), prefixBits: 7, firstByte: 0x80, into: &output)
        return output
    }

    /// An Insert Count Increment of `increment` (RFC 9204 §4.4.3: `00` + a 6-bit prefix) — sent after
    /// applying that many encoder-stream inserts, so the peer encoder learns the entries are usable.
    public static func insertCountIncrement(_ increment: Int) -> [UInt8] {
        var output: [UInt8] = []
        QPACKInteger.encode(increment, prefixBits: 6, firstByte: 0x00, into: &output)
        return output
    }

    /// A Set Dynamic Table Capacity instruction (RFC 9204 §4.3.1: the `001` pattern + a 5-bit prefix) —
    /// sent once before the first insert to size the encoder's dynamic table.
    public static func setDynamicTableCapacity(_ capacity: Int) -> [UInt8] {
        var output: [UInt8] = []
        QPACKInteger.encode(capacity, prefixBits: 5, firstByte: 0x20, into: &output)
        return output
    }

    /// An Insert With Name Reference to the static table (RFC 9204 §4.3.2: the `1` + `T=1` pattern, a
    /// 6-bit-prefix static name index, then the literal value).
    public static func insertWithStaticName(index: Int, value: [UInt8]) -> [UInt8] {
        var output: [UInt8] = []
        QPACKInteger.encode(index, prefixBits: 6, firstByte: 0xC0, into: &output)  // 1, T=1
        QPACKString.encode(value, prefixBits: 7, into: &output)
        return output
    }

    /// An Insert With Literal Name (RFC 9204 §4.3.3: the `01` pattern, a 5-bit-prefix literal name — the
    /// H bit is set by the string codec — then the literal value).
    public static func insertWithLiteralName(name: [UInt8], value: [UInt8]) -> [UInt8] {
        var output: [UInt8] = []
        QPACKString.encode(name, prefixBits: 5, firstByte: 0x40, into: &output)  // 01, + H
        QPACKString.encode(value, prefixBits: 7, into: &output)
        return output
    }

    // MARK: Parsers (violation detection)

    /// Parses complete encoder-stream instructions from `reader`, advancing past each (RFC 9204 §4.3).
    ///
    /// Only a Set Dynamic Table Capacity within `maxCapacity` is permitted; any insert or duplicate, or
    /// an over-capacity set, is `QPACK_ENCODER_STREAM_ERROR`. A partial trailing instruction is left
    /// unconsumed for the next call.
    public static func parseEncoderStream(
        _ reader: inout ByteReader, maxCapacity: Int
    ) throws(QPACKError) {
        while let first = reader.peek() {
            if first & 0x80 != 0 {
                throw .encoderStreamError("insert with name reference (dynamic table disabled)")
            }
            if first & 0x40 != 0 {
                throw .encoderStreamError("insert with literal name (dynamic table disabled)")
            }
            guard first & 0x20 != 0 else {
                throw .encoderStreamError("duplicate (dynamic table disabled)")
            }
            guard try consumeSetCapacity(&reader, maxCapacity: maxCapacity) else {
                return
            }
        }
    }

    /// Parses complete decoder-stream instructions from `reader`, advancing past each (RFC 9204 §4.4).
    ///
    /// An Insert Count Increment or Section Acknowledgment is `QPACK_DECODER_STREAM_ERROR` (this
    /// endpoint sends no inserts and only RIC-0 field sections); a Stream Cancellation is consumed and
    /// ignored. A partial trailing instruction is left unconsumed for the next call.
    public static func parseDecoderStream(_ reader: inout ByteReader) throws(QPACKError) {
        while let first = reader.peek() {
            if first & 0x80 != 0 {
                // §4.4.1 Section Acknowledgment — refers to a stream whose sections are all RIC 0.
                throw .decoderStreamError("Section Acknowledgment for a zero-insert stream")
            }
            if first & 0x40 != 0 {
                // §4.4.2 Stream Cancellation — consumed and ignored (no dynamic-table state).
                guard try consumeStreamCancellation(&reader) else {
                    return
                }
            }
            else {
                // §4.4.3 Insert Count Increment — always a violation here (no inserts were sent).
                guard try consumeInsertCountIncrement(&reader) else {
                    return
                }
            }
        }
    }

    // MARK: Instruction bodies

    /// Consumes a Set Dynamic Table Capacity (§4.3.1); returns false if it is truncated (need more).
    private static func consumeSetCapacity(
        _ reader: inout ByteReader, maxCapacity: Int
    ) throws(QPACKError) -> Bool {
        var probe = reader
        switch QPACKInteger.decode(&probe, prefixBits: 5) {
            case .value(let capacity):
                guard capacity <= maxCapacity else {
                    throw .encoderStreamError("Set Dynamic Table Capacity exceeds the limit")
                }
                reader.advance(by: probe.position - reader.position)
                return true
            case .incomplete:
                return false
            case .overflow:
                throw .encoderStreamError("invalid Set Dynamic Table Capacity")
        }
    }

    /// Consumes a Stream Cancellation (§4.4.2); returns false if it is truncated (need more).
    private static func consumeStreamCancellation(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> Bool {
        var probe = reader
        switch QPACKInteger.decode(&probe, prefixBits: 6) {
            case .value:
                reader.advance(by: probe.position - reader.position)
                return true
            case .incomplete:
                return false
            case .overflow:
                throw .decoderStreamError("invalid Stream Cancellation")
        }
    }

    /// Consumes an Insert Count Increment (§4.4.3) — always a violation here; false if truncated.
    private static func consumeInsertCountIncrement(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> Bool {
        var probe = reader
        switch QPACKInteger.decode(&probe, prefixBits: 6) {
            case .value(let increment):
                throw .decoderStreamError(
                    increment == 0
                        ? "Insert Count Increment of 0"
                        : "Insert Count Increment beyond what the encoder sent"
                )
            case .incomplete:
                return false
            case .overflow:
                throw .decoderStreamError("invalid Insert Count Increment")
        }
    }
}
