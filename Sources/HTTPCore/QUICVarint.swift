//
//  QUICVarint.swift
//  HTTPCore
//
//  RFC 9000 §16 — the QUIC variable-length integer. The two most-significant bits of the first octet
//  encode the length as a power of two (00→1, 01→2, 10→4, 11→8 octets); the remaining bits are the
//  value in network byte order. This yields a 6-, 14-, 30-, or 62-bit unsigned integer. Shared by
//  HTTP/3 framing (RFC 9114 §7.1) and QPACK (RFC 9204) — a different codec from HPACK's §5.1 prefix
//  integer, so it lives on its own. Iterative; no recursion.
//

/// The RFC 9000 §16 variable-length integer codec.
public enum QUICVarint {
    /// The largest value representable — a 62-bit unsigned integer (RFC 9000 §16).
    public static let maxValue: UInt64 = (1 << 62) - 1

    /// The encoded length, in octets, of the varint starting with `firstByte` (RFC 9000 §16).
    ///
    /// The length is `2^(firstByte >> 6)`: the two high bits select 1, 2, 4, or 8 octets.
    public static func encodedLength(firstByte: UInt8) -> Int {
        1 << (Int(firstByte) >> 6)
    }

    /// The minimal number of octets needed to encode `value` (RFC 9000 §16).
    public static func encodedLength(of value: UInt64) -> Int {
        switch value {
            case 0 ... 63: 1
            case 64 ... 16_383: 2
            case 16_384 ... 1_073_741_823: 4
            default: 8
        }
    }

    /// Encodes `value` in its minimal form, appending to `output` (RFC 9000 §16).
    ///
    /// `value` must be at most ``maxValue``; the 8-octet form masks the two length-selector bits so an
    /// out-of-range input can never corrupt the length prefix (fail closed rather than emit garbage).
    public static func encode(_ value: UInt64, into output: inout [UInt8]) {
        switch value {
            case 0 ... 63:
                output.append(UInt8(value))
            case 64 ... 16_383:
                output.append(UInt8(0x40 | (value >> 8)))
                output.append(UInt8(value & 0xFF))
            case 16_384 ... 1_073_741_823:
                output.append(UInt8(0x80 | (value >> 24)))
                output.append(UInt8((value >> 16) & 0xFF))
                output.append(UInt8((value >> 8) & 0xFF))
                output.append(UInt8(value & 0xFF))
            default:
                output.append(UInt8(0xC0 | ((value >> 56) & 0x3F)))
                output.append(UInt8((value >> 48) & 0xFF))
                output.append(UInt8((value >> 40) & 0xFF))
                output.append(UInt8((value >> 32) & 0xFF))
                output.append(UInt8((value >> 24) & 0xFF))
                output.append(UInt8((value >> 16) & 0xFF))
                output.append(UInt8((value >> 8) & 0xFF))
                output.append(UInt8(value & 0xFF))
        }
    }

    /// Decodes a varint from `reader`, advancing it (RFC 9000 §16).
    ///
    /// Returns `nil` — leaving `reader` unmoved — when fewer than the full encoded octets are present,
    /// so an incremental parser can treat a short read as "need more bytes" rather than an error. A
    /// varint always fits in 62 bits, so truncation is the only failure mode.
    public static func decode(_ reader: inout ByteReader) -> UInt64? {
        guard let first = reader.peek() else { return nil }
        let length = encodedLength(firstByte: first)
        guard reader.remaining >= length else { return nil }
        var value = UInt64(first & 0x3F)
        reader.advance()
        for _ in 1 ..< length {
            guard let byte = reader.readByte() else { return nil }  // guarded by `remaining` above
            value = (value << 8) | UInt64(byte)
        }
        return value
    }
}
