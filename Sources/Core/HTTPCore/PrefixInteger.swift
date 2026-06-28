//
//  PrefixInteger.swift
//  HTTPCore
//
//  RFC 7541 §5.1 — the prefix-integer representation shared by HPACK (RFC 7541) and QPACK
//  (RFC 9204 §4.1.1): an N-bit prefix plus a variable-length run of 7-bit continuation octets (high
//  bit = "more follow"). This is the single audited home for the codec — and, critically, for the
//  overflow / oversized-length guard the RFC warns about in §5.1, so that security-relevant bounds
//  check lives in exactly one place rather than being copied per protocol. `HPACKInteger` and
//  `QPACKInteger` are thin adapters over this type.
//
//  Distinct from the QUIC variable-length integer (RFC 9000 §16) that HTTP/3 framing uses — the `(N+)`
//  notation in RFC 7541 / RFC 9204 is this prefix integer, not the `(i)` QUIC varint.
//
//  The decoder is iterative (no recursion) and reports the three outcomes its callers must distinguish:
//  a value, a truncation (the octet run ended mid-integer — on QPACK's incremental encoder/decoder
//  streams this means "need more bytes"), and an overflow (a hard fault). Each protocol's codec maps
//  these to its own error vocabulary.
//

/// The RFC 7541 §5.1 prefix-integer codec shared by HPACK and QPACK.
public enum PrefixInteger {
    /// The largest integer the decoder accepts before reporting overflow (RFC 7541 §5.1).
    ///
    /// Prefix integers index tables or size strings, so an unbounded value is a resource-exhaustion
    /// vector; `Int32.max` is far above any legitimate header construct yet safely clear of `Int`
    /// overflow.
    public static let maxValue = Int(Int32.max)

    /// The result of decoding a prefix integer.
    public enum Outcome: Sendable, Equatable {
        /// A fully decoded value.
        case value(Int)
        /// The octet run ended before the integer completed — truncated input.
        case incomplete
        /// The value exceeded ``maxValue`` — an overflow / oversized-length fault.
        case overflow
    }

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
    /// Reports ``Outcome/incomplete`` on truncation (so a streaming parser can wait for more) and
    /// ``Outcome/overflow`` on a value past ``maxValue``. The reader is left unspecified on a
    /// non-`value` outcome — callers that need to retry snapshot it first.
    public static func decode(_ reader: inout ByteReader, prefixBits: Int) -> Outcome {
        guard let first = reader.readByte() else {
            return .incomplete
        }
        let prefixMask = (1 << prefixBits) - 1
        var value = Int(first) & prefixMask
        if value < prefixMask {
            return .value(value)
        }

        var shift = 0
        while true {
            guard let byte = reader.readByte() else {
                return .incomplete
            }
            // Bound the running total *before* adding, so it can never overflow `Int` (§5.1).
            let added = Int(byte & 0x7F) << shift
            guard added <= maxValue - value else {
                return .overflow
            }
            value += added
            if byte & 0x80 == 0 {
                return .value(value)
            }
            shift += 7
            // At most five continuation octets are needed for any value up to `maxValue`; more is a
            // padding attack (an endless run of 0x80 octets that never terminates).
            guard shift < 32 else {
                return .overflow
            }
        }
    }
}
