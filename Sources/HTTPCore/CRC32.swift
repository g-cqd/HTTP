//
//  CRC32.swift
//  HTTPCore
//
//  RFC 1952 §8 — the CRC-32 (ITU-T V.42, reflected polynomial 0xEDB88320) that gzip appends to its
//  payload as an integrity check. Table-driven, one octet at a time; the 256-entry table is built once
//  on first use. Iterative; no recursion.
//

/// The CRC-32 checksum used by gzip (RFC 1952 §8).
public enum CRC32 {

    /// The per-octet update table for the reflected polynomial `0xEDB88320`, computed once.
    private static let table: [UInt32] = (0..<256).map { index in
        var crc = UInt32(index)
        for _ in 0..<8 {
            crc = (crc & 1) != 0 ? (0xEDB8_8320 ^ (crc >> 1)) : (crc >> 1)
        }
        return crc
    }

    /// The CRC-32 of `bytes` (RFC 1952 §8).
    ///
    /// The standard check value of `"123456789"` is `0xCBF43926`.
    public static func checksum<Bytes: Sequence>(_ bytes: Bytes) -> UInt32
    where Bytes.Element == UInt8 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc = table[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }
}
