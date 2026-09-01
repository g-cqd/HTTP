//
//  RandomToken.swift
//  HTTPCore
//
//  The package's one 128-bit random identifier rendering (session ids, request correlation ids). The
//  fixed width is the point: `String(high, radix: 16) + String(low, radix: 16)` drops leading zeros, so
//  it is NOT injective — `(0x1, 0x23)` and `(0x12, 0x3)` both render "123", and one session id can then
//  be presented as another (CWE-1288, improper validation of an unsafe equivalence in input).
//  Zero-padding each half to 16 digits restores injectivity. Entropy comes from
//  `SystemRandomNumberGenerator`, documented to draw from the platform CSPRNG, so the dependency-free
//  core needs no crypto library for an unguessable token. One allocation: the `String` buffer, filled in
//  place — no intermediate byte array and no concatenation of two renderings.
//

/// A cryptographically random 128-bit token as exactly 32 lowercase hex digits.
///
/// Fixed width, so the rendering is injective: two distinct 128-bit values always render to two
/// distinct strings. Concatenating two `String(_:radix:)` renderings is not (CWE-1288 — an ambiguous
/// identifier lets one session id be presented as another).
public enum RandomToken {
    /// The number of hex digits in a 128-bit token (two 64-bit words at 16 digits each).
    private static let digitCount = 32

    /// A fresh 128-bit token from the system CSPRNG, as 32 lowercase hex digits.
    public static func hex128() -> String {
        var generator = SystemRandomNumberGenerator()
        return hex128(using: &generator)
    }

    /// The 32-digit rendering of the next two 64-bit words from `generator`.
    ///
    /// The injected-generator seam: a test scripts the exact words whose rendering it wants to pin.
    /// Production callers use ``hex128()``, which supplies the system CSPRNG.
    static func hex128(using generator: inout some RandomNumberGenerator) -> String {
        let high = generator.next()
        let low = generator.next()
        return String(unsafeUninitializedCapacity: digitCount) { buffer in
            writeHex(high, into: buffer, at: 0)
            writeHex(low, into: buffer, at: 16)
            return digitCount
        }
    }

    /// Writes `value` as 16 big-endian lowercase hex digits starting at `offset`.
    private static func writeHex(
        _ value: UInt64,
        into buffer: UnsafeMutableBufferPointer<UInt8>,
        at offset: Int
    ) {
        for index in 0 ..< 16 {
            let nibble = UInt8(truncatingIfNeeded: (value >> UInt64(60 - index * 4)) & 0xF)
            // Arithmetic rather than a `static let` digit table: a stored global pays a
            // lazy-initialization check on every one of these 32 reads, and the branch here is
            // perfectly predictable per digit class.
            buffer[offset + index] = nibble < 10 ? 0x30 &+ nibble : 0x57 &+ nibble
        }
    }
}
