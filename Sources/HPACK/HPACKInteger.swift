//
//  HPACKInteger.swift
//  HPACK
//
//  RFC 7541 §5.1 — integer representation. An integer is split into an N-bit prefix and a
//  variable-length sequence of continuation octets (7 payload bits each, high bit = "more follow").
//  The codec is iterative (no recursion) and bounds the decoded magnitude, defusing the overflow and
//  oversized-length attacks the RFC warns about in §5.1.
//

public import HTTPCore

/// The RFC 7541 §5.1 prefix-integer codec.
public enum HPACKInteger {

    /// The largest integer the decoder accepts before failing closed.
    ///
    /// HPACK integers index tables or size strings, so an unbounded value is a resource-exhaustion
    /// vector; RFC 7541 §5.1 requires a limit. `Int32.max` is far above any legitimate header
    /// construct yet safely clear of overflow.
    public static let maxValue = Int(Int32.max)

    /// Encodes `value` with a `prefixBits`-bit prefix (RFC 7541 §5.1).
    ///
    /// The low `prefixBits` of the first octet hold the prefix; its high bits carry the
    /// representation's flags, supplied pre-set in `firstByte`. Continuation octets follow as needed.
    public static func encode(
        _ value: Int,
        prefixBits: Int,
        firstByte: UInt8 = 0,
        into output: inout [UInt8]
    ) {
        let limit = (1 << prefixBits) - 1
        if value < limit {
            output.append(firstByte | UInt8(value))
            return
        }
        output.append(firstByte | UInt8(limit))
        var remainder = value - limit
        while remainder >= 0x80 {
            output.append(UInt8(remainder & 0x7F) | 0x80)
            remainder >>= 7
        }
        output.append(UInt8(remainder))
    }

    /// Decodes a `prefixBits`-bit prefix integer from `reader` (RFC 7541 §5.1).
    ///
    /// Reads the first octet and masks off the flag bits, then accumulates any continuation octets.
    /// Fails closed on truncation or on a value that would exceed ``maxValue`` (overflow guard).
    public static func decode(
        _ reader: inout ByteReader,
        prefixBits: Int
    ) throws(HPACKError) -> Int {
        guard let first = reader.readByte() else { throw .truncatedInteger }
        let prefixMask = (1 << prefixBits) - 1
        var value = Int(first) & prefixMask
        if value < prefixMask { return value }

        var shift = 0
        while true {
            guard let byte = reader.readByte() else { throw .truncatedInteger }
            // Bound the running total *before* adding, so it can never overflow `Int` (§5.1).
            let added = Int(byte & 0x7F) << shift
            guard added <= maxValue - value else { throw .integerOverflow }
            value += added
            if byte & 0x80 == 0 { return value }
            shift += 7
            // At most five continuation octets are needed for any value up to `maxValue`; more is a
            // padding attack (an endless run of 0x80 octets that never terminates).
            guard shift < 32 else { throw .integerOverflow }
        }
    }
}
