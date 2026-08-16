//
//  CRC32BackendTests.swift
//  HTTPCoreTests
//
//  Cross-validates every CRC32.Backend (slicing-by-1/-8, ARM, x86, and the auto pick) against the
//  portable byte-at-a-time reference over the standard check value and a range of sizes / pseudo-random
//  buffers — so a hardware backend can never silently disagree on the gzip integrity check (RFC 1952
//  §8). A wrong polynomial / byte order / slicing index would surface here, not as corrupt output.
//  This is the portable-vs-hardware differential on whatever CPU runs it: on aarch64 (Apple Silicon,
//  the Linux CI container) `.arm` and `.fastest` *are* the ARMv8 hardware path, selected
//  unconditionally at compile time; on x86 with PCLMULQDQ, `.x86` and `.fastest` are the in-house
//  carry-less-multiply folding kernel. The off-arch backends fold through the portable table.
//

import HTTPCore
import Testing

@Suite("RFC 1952 §8 — CRC-32 backends agree")
struct CRC32BackendTests {
    private static let backends: [CRC32.Backend] = [.fastest, .sliceBy1, .sliceBy8, .arm, .x86]

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

    @Test(
        "every backend matches the reference on large buffers (deep fold-by-4 steady state)",
        arguments: [4_096, 4_099, 8_192 + 63]
    )
    func matchesReferenceOnLargeBuffers(size: Int) {
        // The x86 PCLMULQDQ kernel only engages at >= 64 bytes and streams four 128-bit accumulators
        // per 64-byte stride; these sizes push it (and the ARM/table paths) well past the boundary
        // cases into the steady state, with both aligned and ragged tails.
        var seed: UInt64 = 0x9E37_79B9_7F4A_7C15
        let buffer: [UInt8] = (0 ..< size)
            .map { _ in
                seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
                return UInt8(truncatingIfNeeded: seed >> 56)
            }
        let expected = reference(buffer)
        for backend in Self.backends {
            #expect(
                CRC32.checksum(buffer, backend: backend) == expected,
                "backend \(backend) disagreed at size \(size)")
        }
    }
}
