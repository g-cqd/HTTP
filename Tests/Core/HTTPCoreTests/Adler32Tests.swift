//
//  Adler32Tests.swift
//  HTTPCoreTests
//
//  RFC 1950 §9 — the Adler-32 a zlib stream carries in its trailer, which is the only integrity check
//  a `Content-Encoding: deflate` body with a zlib wrapper has. Pinned against the published vectors
//  and cross-checked against the naive one-octet-at-a-time definition, because the blocked form
//  defers the modulo and is exactly where an overflow would hide.
//

import HTTPCore
import Testing

/// The definition straight from RFC 1950 §9, one octet at a time — the reference the fast path must
/// agree with.
private func referenceAdler32(_ bytes: [UInt8]) -> UInt32 {
    var low: UInt32 = 1
    var high: UInt32 = 0
    for byte in bytes {
        low = (low + UInt32(byte)) % 65_521
        high = (high + low) % 65_521
    }
    return high << 16 | low
}

/// Published input → checksum vectors.
private let adlerVectors: [(input: String, checksum: UInt32)] = [
    ("", 0x0000_0001),
    ("a", 0x0062_0062),
    ("abc", 0x024D_0127),
    ("Wikipedia", 0x11E6_0398),
    ("123456789", 0x091E_01DE)
]

@Test("the published Adler-32 vectors match (RFC 1950 §9)", arguments: adlerVectors)
func adler32MatchesPublishedVectors(input: String, checksum: UInt32) {
    #expect(Adler32.checksum(Array(input.utf8)) == checksum)
}

@Test(
    "the blocked form agrees with the one-octet definition at and past the modulo window",
    arguments: [0, 1, 255, 5_551, 5_552, 5_553, 11_104, 40_000]
)
func adler32AgreesWithTheReference(count: Int) {
    // 0xFF maximizes the deferred sums, so a block boundary off by one — or an overflow in the
    // 5_552-octet window RFC 1950 §9's NMAX is chosen to make impossible — shows up here.
    let bytes = [UInt8](repeating: 0xFF, count: count)
    #expect(Adler32.checksum(bytes) == referenceAdler32(bytes))
}

@Test("a non-contiguous sequence checksums identically to its contiguous form")
func adler32HandlesNonContiguousInput() {
    let bytes = (0 ..< 4_096).map { UInt8(truncatingIfNeeded: $0 &* 7) }
    #expect(Adler32.checksum(AnySequence(bytes)) == Adler32.checksum(bytes))
}

@Test("a single flipped octet changes the checksum")
func adler32DetectsCorruption() {
    var bytes = Array("the quick brown fox".utf8)
    let original = Adler32.checksum(bytes)
    bytes[7] ^= 0x01
    #expect(Adler32.checksum(bytes) != original)
}
