//
//  CRC32RunningTests.swift
//  HTTPCoreTests
//
//  ``CRC32/Running`` is the incremental form of the gzip integrity check (RFC 1952 §8): a gzip member
//  produced by a streaming encoder cannot hold its payload to checksum it at the end, so the CRC has to
//  be folded chunk by chunk. These pin the only property that matters — the running value after any
//  chunking equals the one-shot checksum of the concatenation — across chunk sizes that straddle the
//  slicing-by-8 stride and every tail length.
//

import HTTPCore
import Testing

/// Deterministic pseudo-random bytes (SplitMix-style), so a failure is reproducible.
private func sample(_ count: Int) -> [UInt8] {
    var seed: UInt64 = 0x2545_F491_4F6C_DD1D
    return (0 ..< count)
        .map { _ in
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return UInt8(truncatingIfNeeded: seed >> 56)
        }
}

@Test(
    "RFC 1952 §8 — a chunked running CRC-32 equals the one-shot checksum",
    arguments: [1, 2, 3, 7, 8, 9, 64, 1_000]
)
func runningMatchesOneShot(chunk: Int) {
    let bytes = sample(4_099)
    var running = CRC32.Running()
    for start in stride(from: 0, to: bytes.count, by: chunk) {
        running.update(bytes[start ..< min(start + chunk, bytes.count)])
    }
    #expect(running.checksum == CRC32.checksum(bytes))
}

@Test("RFC 1952 §8 — a fresh running CRC-32 is the checksum of the empty input")
func runningStartsEmpty() {
    #expect(CRC32.Running().checksum == CRC32.checksum([UInt8]()))
}

@Test("RFC 1952 §8 — the running CRC-32 reaches the standard check value 0xCBF43926")
func runningReachesStandardCheck() {
    var running = CRC32.Running()
    for byte in Array("123456789".utf8) {
        running.update(CollectionOfOne(byte))
    }
    #expect(running.checksum == 0xCBF4_3926)
}

@Test("RFC 1952 §8 — a non-contiguous chunk folds through the portable table")
func runningFoldsNonContiguousInput() {
    let bytes = sample(257)
    var running = CRC32.Running()
    running.update(AnySequence(bytes))
    #expect(running.checksum == CRC32.checksum(bytes))
}
