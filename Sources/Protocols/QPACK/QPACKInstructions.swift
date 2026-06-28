//
//  QPACKInstructions.swift
//  QPACK
//
//  RFC 9204 §4.3 (encoder stream) / §4.4 (decoder stream) — generators for the QPACK instruction
//  streams. The dynamic encoder emits its inserts per field section (Set Dynamic Table Capacity, then
//  Insert With Name Reference / Literal Name on the encoder stream), and the decoder emits Section
//  Acknowledgment / Insert Count Increment on the decoder stream. Each instruction is a
//  prefix-integer-framed opcode (RFC 9204 §4.1.1), so the bodies are small and allocation-light.
//

/// Generators for the QPACK encoder/decoder instruction streams (RFC 9204 §4.3/§4.4).
public enum QPACKInstructions {
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
}
