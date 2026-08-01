//
//  CRC32.swift
//  HTTPCore
//
//  RFC 1952 §8 — the CRC-32 (ITU-T V.42, reflected polynomial 0xEDB88320) that gzip appends to its
//  payload as an integrity check. Contiguous input dispatches to a hardware / SWAR backend (`CCRC32`:
//  the ARMv8 CRC32 instructions, zlib's PCLMULQDQ on x86, or a portable slicing-by-8 table); a
//  non-contiguous sequence uses a byte-at-a-time table loop (also the cross-check reference).
//  Iterative; no recursion.
//

internal import CCRC32

/// The CRC-32 checksum used by gzip (RFC 1952 §8).
public enum CRC32 {
    /// A CRC-32 implementation.
    ///
    /// Every backend produces the identical checksum (RFC 1952 §8) — they differ only in speed, and
    /// each falls back to the portable table when its CPU feature is unavailable.
    public enum Backend: Sendable {
        /// The fastest backend available on this CPU (the default).
        case fastest
        /// The naive one-octet table (the original algorithm) — a portable, low-memory baseline.
        case sliceBy1
        /// The portable slicing-by-8 table — deterministic across machines.
        case sliceBy8
        /// zlib's `crc32` (internally hardware-accelerated, e.g. PCLMULQDQ on x86).
        case zlib
        /// ARMv8 CRC32 instructions (table fallback off aarch64).
        case arm
        /// The x86-64 hardware path — zlib's PCLMULQDQ (table fallback off x86-64).
        case x86
    }

    /// A CRC-32 folded incrementally over chunks (RFC 1952 §8).
    ///
    /// The seeded form of ``CRC32/checksum(_:backend:)``, for a producer that never holds the whole
    /// payload: a streaming gzip encoder has to emit the trailer without having retained the octets it
    /// checksummed. ``checksum`` after the last ``update(_:)`` equals the one-shot checksum of the
    /// concatenation, and after *any* prefix it equals the checksum of that prefix.
    ///
    /// Nested here rather than given its own file because it folds through this type's portable table
    /// on the non-contiguous path, exactly as ``Backend`` shares its dispatch.
    public struct Running: Sendable {
        /// The checksum of everything folded in so far — the value gzip appends once the input ends.
        public private(set) var checksum: UInt32 = 0

        /// Creates a running checksum positioned at the empty input.
        public init() {
            // The CRC-32 of the empty input is 0, which is the property's initial value.
        }

        /// Folds `bytes` into the running checksum.
        ///
        /// Contiguous input goes to the same accelerated backend ``CRC32/checksum(_:backend:)`` picks
        /// by default; a non-contiguous sequence folds through the portable byte-at-a-time table.
        public mutating func update<Bytes: Sequence>(_ bytes: Bytes) where Bytes.Element == UInt8 {
            let folded = bytes.withContiguousStorageIfAvailable { buffer -> UInt32 in
                guard let base = buffer.baseAddress else {
                    return checksum
                }
                return ccrc32_update(checksum, base, buffer.count)
            }
            if let folded {
                checksum = folded
                return
            }
            var crc = checksum ^ 0xFFFF_FFFF
            for byte in bytes {
                crc = CRC32.referenceTable[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
            }
            checksum = crc ^ 0xFFFF_FFFF
        }
    }

    /// The CRC-32 of `bytes` (RFC 1952 §8).
    ///
    /// The standard check value of `"123456789"` is `0xCBF43926`. Contiguous input uses the chosen
    /// hardware / SWAR `backend`; a non-contiguous sequence uses a portable byte-at-a-time loop.
    public static func checksum<Bytes: Sequence>(
        _ bytes: Bytes,
        backend: Backend = .fastest
    ) -> UInt32 where Bytes.Element == UInt8 {
        if let result = bytes.withContiguousStorageIfAvailable({ accelerated($0, backend) }) {
            return result
        }
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc = referenceTable[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }

    private static func accelerated(
        _ buffer: UnsafeBufferPointer<UInt8>,
        _ backend: Backend
    ) -> UInt32 {
        guard let base = buffer.baseAddress, !buffer.isEmpty else {
            return 0  // CRC-32 of "" is 0
        }
        switch backend {
            case .fastest:
                return ccrc32(base, buffer.count)
            case .sliceBy1:
                return ccrc32_slice1(base, buffer.count)
            case .sliceBy8:
                return ccrc32_slice8(base, buffer.count)
            case .zlib:
                return ccrc32_zlib(base, buffer.count)
            case .arm:
                return ccrc32_arm(base, buffer.count)
            case .x86:
                return ccrc32_x86(base, buffer.count)
        }
    }

    /// The per-octet table for the non-contiguous fallback (reflected polynomial `0xEDB88320`).
    private static let referenceTable: [UInt32] = (0 ..< 256)
        .map { index in
            var crc = UInt32(index)
            for _ in 0 ..< 8 {
                crc = (crc & 1) != 0 ? (0xEDB8_8320 ^ (crc >> 1)) : (crc >> 1)
            }
            return crc
        }
}
