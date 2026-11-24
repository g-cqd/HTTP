//
//  CRC32.swift
//  HTTPCore
//
//  RFC 1952 §8 — the CRC-32 (ITU-T V.42, reflected polynomial 0xEDB88320) that gzip appends to its
//  payload as an integrity check. Contiguous input dispatches through `AemiKernels.crc32IEEE`
//  (promoted into `CAemiKernels`: ARMv8 CRC32 on arm64, CPUID-dispatched PCLMULQDQ 4-way folding on
//  x86, or portable slicing-by-8 scalar fallback); a non-contiguous sequence uses a byte-at-a-time
//  table loop (also the cross-check reference). Iterative; no recursion.
//

internal import AemiKernels

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
        /// ARMv8 CRC32 instructions (table fallback off aarch64).
        case arm
        /// The x86 hardware path — an in-house PCLMULQDQ folding kernel, CPUID-dispatched.
        case x86
    }

    /// A CRC-32 folded incrementally over chunks (RFC 1952 §8).
    public struct Running: Sendable {
        /// The checksum of everything folded in so far — the value gzip appends once the input ends.
        public private(set) var checksum: UInt32 = 0

        /// Creates a running checksum positioned at the empty input.
        public init() {
            // The CRC-32 of the empty input is 0, which is the property's initial value.
        }

        /// Folds `bytes` into the running checksum.
        public mutating func update<Bytes: Sequence>(_ bytes: Bytes) where Bytes.Element == UInt8 {
            let folded = bytes.withContiguousStorageIfAvailable { buffer -> UInt32 in
                guard let base = buffer.baseAddress, !buffer.isEmpty else {
                    return checksum
                }
                let raw = unsafe AemiKernels.crc32IEEE(
                    checksum ^ 0xFFFF_FFFF,
                    base,
                    count: buffer.count
                )
                return raw ^ 0xFFFF_FFFF
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
        if let result = bytes.withContiguousStorageIfAvailable({ unsafe accelerated($0, backend) })
        {
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
            return 0
        }
        if backend == .sliceBy1 {
            var crc: UInt32 = 0xFFFF_FFFF
            for i in 0 ..< buffer.count {
                crc = referenceTable[Int((crc ^ UInt32(unsafe buffer[i])) & 0xFF)] ^ (crc >> 8)
            }
            return crc ^ 0xFFFF_FFFF
        }
        let kernelBackend = resolvedKernelBackend(for: backend)
        let raw = unsafe AemiKernels.crc32IEEE(
            0xFFFF_FFFF,
            base,
            count: buffer.count,
            backend: kernelBackend
        )
        return raw ^ 0xFFFF_FFFF
    }

    private static func resolvedKernelBackend(for backend: Backend) -> AemiKernels.Backend {
        switch backend {
            case .fastest:
                return .fastest
            case .sliceBy8, .sliceBy1:
                return .scalar
            case .arm:
                #if arch(arm64)
                    return .fastest
                #else
                    return .scalar
                #endif
            case .x86:
                #if arch(x86_64) || arch(i386)
                    return .fastest
                #else
                    return .scalar
                #endif
        }
    }

    /// Standard reflected IEEE 802.3 / ISO-HDLC 256-entry lookup table (`0xEDB88320`).
    private static let referenceTable: [UInt32] = (0 ..< 256)
        .map { entry in
            var c = UInt32(entry)
            for _ in 0 ..< 8 {
                c = (c & 1) == 1 ? (0xEDB8_8320 ^ (c >> 1)) : (c >> 1)
            }
            return c
        }
}
