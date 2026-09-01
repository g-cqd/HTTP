//
//  Adler32.swift
//  HTTPCore
//
//  RFC 1950 §9 — the checksum a zlib stream carries in its 4-octet trailer, and therefore the only
//  integrity check a zlib-wrapped `Content-Encoding: deflate` body has (gzip has CRC-32 instead; see
//  CRC32.swift). Two sums modulo 65521, with the modulo deferred across a 5552-octet window: the
//  constant RFC 1950 §9 calls NMAX, chosen as the largest window for which the deferred sums cannot
//  overflow 32 bits. Iterative; no recursion.
//

/// The Adler-32 checksum used by zlib (RFC 1950 §9).
public enum Adler32 {
    /// The modulus — the largest prime below 65536 (RFC 1950 §9).
    private static let modulus: UInt32 = 65_521

    /// NMAX: the most octets that may be summed before reducing.
    ///
    /// RFC 1950 §9's derivation — `255 × n(n+1)/2 + (n+1)(modulus - 1) <= 2^32 - 1` — makes 5552 the
    /// largest safe window, which is why the accumulation below can use wrapping addition without a
    /// wrap ever being reachable.
    private static let window = 5_552

    /// The Adler-32 of `bytes` (RFC 1950 §9).
    ///
    /// The checksum of the empty input is `1`, and of `"Wikipedia"` is `0x11E60398`. Contiguous input
    /// takes the blocked path; a non-contiguous sequence reduces on every octet.
    public static func checksum<Bytes: Sequence>(_ bytes: Bytes) -> UInt32
    where Bytes.Element == UInt8 {
        if let result = bytes.withContiguousStorageIfAvailable(blocked) {
            return result
        }
        var low: UInt32 = 1
        var high: UInt32 = 0
        for byte in bytes {
            low = (low &+ UInt32(byte)) % modulus
            high = (high &+ low) % modulus
        }
        return high << 16 | low
    }

    /// The blocked accumulation: sum a whole ``window`` before reducing, which is where the speed is.
    private static func blocked(_ buffer: UnsafeBufferPointer<UInt8>) -> UInt32 {
        var low: UInt32 = 1
        var high: UInt32 = 0
        var index = 0
        while index < buffer.count {
            let end = min(index &+ window, buffer.count)
            while index < end {
                low &+= UInt32(buffer[index])
                high &+= low
                index &+= 1
            }
            low %= modulus
            high %= modulus
        }
        return high << 16 | low
    }
}
