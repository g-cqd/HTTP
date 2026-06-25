//
//  CRC32BackendTests.swift
//  HTTPCoreTests
//
//  Cross-validates every CRC32.Backend (slicing-by-8, zlib, ARM, x86, and the auto pick) against the
//  portable byte-at-a-time reference over the standard check value and a range of sizes / pseudo-random
//  buffers — so a hardware backend can never silently disagree on the gzip integrity check (RFC 1952
//  §8). A wrong polynomial / byte order / slicing index would surface here, not as corrupt output.
//

import HTTPCore
import Testing

@Suite("RFC 1952 §8 — CRC-32 backends agree")
struct CRC32BackendTests {
    private static let backends: [CRC32.Backend] = [.fastest, .sliceBy8, .zlib, .arm, .x86]

    /// The reference value: a non-contiguous sequence routes through the byte-at-a-time fallback loop.
    private func reference(_ bytes: [UInt8]) -> UInt32 { CRC32.checksum(AnySequence(bytes)) }

    @Test("every backend yields the standard check value 0xCBF43926")
    func standardCheck() {
        for backend in Self.backends {
            #expect(CRC32.checksum(Array("123456789".utf8), backend: backend) == 0xCBF4_3926)
        }
    }

    @Test("every backend yields zero for the empty input")
    func emptyIsZero() {
        for backend in Self.backends {
            #expect(CRC32.checksum([UInt8](), backend: backend) == 0)
        }
    }

    @Test("every backend matches the reference across sizes (8-byte strides + tails)")
    func matchesReferenceAcrossSizes() {
        // Deterministic pseudo-random bytes (SplitMix-style); sizes 0…600 straddle the 8-byte slicing
        // stride, the 4-byte ARM path, and every tail length.
        var seed: UInt64 = 0x2545_F491_4F6C_DD1D
        func nextByte() -> UInt8 {
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return UInt8(truncatingIfNeeded: seed >> 56)
        }
        var buffer: [UInt8] = []
        for size in 0 ... 600 {
            let expected = reference(buffer)
            for backend in Self.backends {
                #expect(
                    CRC32.checksum(buffer, backend: backend) == expected,
                    "backend \(backend) disagreed at size \(size)")
            }
            buffer.append(nextByte())
        }
    }
}
