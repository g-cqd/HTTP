//
//  QPACKInteger.swift
//  QPACK
//
//  RFC 9204 §4.1.1 — QPACK reuses the HPACK prefix-integer encoding (RFC 7541 §5.1). The codec itself
//  lives in ``PrefixInteger`` (HTTPCore), the single audited home for the shared representation and its
//  §5.1 overflow / oversized-length guard; this type is the QPACK-context face of it. Distinct from the
//  QUIC variable-length integer (RFC 9000 §16) that HTTP/3 framing uses — the `(N+)` notation here is
//  the prefix integer, not the `(i)` QUIC varint.
//
//  The decoder reports the three outcomes its callers must distinguish — a value, a truncation (on the
//  incremental encoder/decoder streams this means "need more bytes"), and an overflow (a hard fault).
//  Each caller maps these to the RFC 9204 §6 code for its context (field section →
//  `QPACK_DECOMPRESSION_FAILED`; instruction streams → the stream error).
//

public import HTTPCore

/// The RFC 9204 §4.1.1 prefix-integer codec — the QPACK face of ``PrefixInteger`` (RFC 7541 §5.1).
public enum QPACKInteger {
    /// The largest integer the decoder accepts before reporting overflow (RFC 7541 §5.1).
    public static let maxValue = PrefixInteger.maxValue

    /// The result of decoding a prefix integer: a value, a truncation, or an overflow.
    public typealias Outcome = PrefixInteger.Outcome

    /// Encodes `value` with a `prefixBits`-bit prefix (RFC 9204 §4.1.1 / RFC 7541 §5.1).
    ///
    /// The low `prefixBits` of the first octet hold the prefix; its high bits carry the
    /// representation's flags, supplied pre-set in `firstByte`. Continuation octets follow as needed.
    public static func encode(
        _ value: Int,
        prefixBits: Int,
        firstByte: UInt8 = 0,
        into output: inout [UInt8]
    ) {
        PrefixInteger.encode(value, prefixBits: prefixBits, firstByte: firstByte, into: &output)
    }

    /// Decodes a `prefixBits`-bit prefix integer from `reader` (RFC 9204 §4.1.1 / RFC 7541 §5.1).
    ///
    /// Reports ``Outcome/incomplete`` on truncation (so a streaming parser can wait for more) and
    /// ``Outcome/overflow`` on a value past ``maxValue``. The reader is left unspecified on a
    /// non-`value` outcome — callers that need to retry snapshot it first.
    public static func decode(_ reader: inout ByteReader, prefixBits: Int) -> Outcome {
        PrefixInteger.decode(&reader, prefixBits: prefixBits)
    }
}
