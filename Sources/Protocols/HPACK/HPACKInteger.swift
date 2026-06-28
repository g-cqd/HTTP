//
//  HPACKInteger.swift
//  HPACK
//
//  RFC 7541 §5.1 — integer representation. The codec itself lives in ``PrefixInteger`` (HTTPCore), the
//  single audited home for the shared HPACK/QPACK representation and its §5.1 overflow /
//  oversized-length guard; this type is the HPACK-context face, mapping the shared decoder's outcome to
//  the throwing `Int` API the HPACK encoder/decoder expects (a truncation or an overflow is a fatal
//  HPACK error).
//

public import HTTPCore

/// The RFC 7541 §5.1 prefix-integer codec — the HPACK face of ``PrefixInteger``.
public enum HPACKInteger {
    /// The largest integer the decoder accepts before failing closed (RFC 7541 §5.1).
    public static let maxValue = PrefixInteger.maxValue

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
        PrefixInteger.encode(value, prefixBits: prefixBits, firstByte: firstByte, into: &output)
    }

    /// Decodes a `prefixBits`-bit prefix integer from `reader` (RFC 7541 §5.1).
    ///
    /// Fails closed on truncation (`.truncatedInteger`) or on a value that would exceed ``maxValue``
    /// (`.integerOverflow`).
    public static func decode(
        _ reader: inout ByteReader,
        prefixBits: Int
    ) throws(HPACKError) -> Int {
        switch PrefixInteger.decode(&reader, prefixBits: prefixBits) {
            case .value(let value):
                return value
            case .incomplete:
                throw .truncatedInteger
            case .overflow:
                throw .integerOverflow
        }
    }
}
