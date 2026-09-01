//
//  Adler32.swift
//  HTTPDeflate
//
//  RFC 1950 §2.2 / §9 — the Adler-32 checksum the zlib envelope carries: `s2·65536 + s1` over
//  prime 65521, seeded at 1. Folded incrementally in the standard 5552-octet batches (the largest
//  run before 32-bit accumulators could overflow), so the zlib decoder verifies streamed output
//  without buffering it.
//

/// The running Adler-32 checksum of the zlib envelope (RFC 1950 §2.2).
struct Adler32 {
    /// The largest batch whose worst-case sums still fit 32 bits (zlib's `NMAX`).
    private static let batchLimit = 5_552
    /// The modulus (the largest prime below 65536, RFC 1950 §9).
    private static let modulus: UInt32 = 65_521

    /// The checksum of everything folded so far (1 for the empty input).
    private(set) var checksum: UInt32 = 1

    /// Folds `bytes` into the checksum.
    mutating func update(_ bytes: Span<UInt8>) {
        var low = checksum & 0xFFFF
        var high = checksum >> 16
        var index = 0
        while index < bytes.count {
            let batch = min(Self.batchLimit, bytes.count - index)
            for offset in 0 ..< batch {
                low &+= UInt32(bytes[index + offset])
                high &+= low
            }
            low %= Self.modulus
            high %= Self.modulus
            index += batch
        }
        checksum = (high << 16) | low
    }
}
