//
//  SHA1.swift
//  WebSocket
//
//  FIPS 180-4 §6.1 — SHA-1, the one hash RFC 6455 §4.2.2 requires for `Sec-WebSocket-Accept`
//  (base64(SHA-1(key ‖ GUID))). A pure-Swift implementation so the handshake needs no CryptoKit
//  (Apple-only) and the module stays cross-platform; it runs once per connection over ~60 bytes, where
//  throughput is irrelevant. SHA-1 is broken for collision resistance, but RFC 6455 uses it only as a
//  fixed handshake transform — not for security — so it is the correct, spec-mandated primitive here.
//

/// FIPS 180-4 §6.1 SHA-1 — a 160-bit digest, used only for the RFC 6455 handshake accept value.
enum SHA1 {
    /// The 20-byte SHA-1 digest of `message` (FIPS 180-4 §6.1.2).
    static func hash(_ message: [UInt8]) -> [UInt8] {
        // §5.3.1 — the initial hash value.
        var h0: UInt32 = 0x6745_2301
        var h1: UInt32 = 0xEFCD_AB89
        var h2: UInt32 = 0x98BA_DCFE
        var h3: UInt32 = 0x1032_5476
        var h4: UInt32 = 0xC3D2_E1F0

        // §5.1.1 — pad with 0x80, zeros, then the 64-bit big-endian message length in bits.
        var padded = message
        let bitLength = UInt64(message.count) &* 8
        padded.append(0x80)
        while padded.count % 64 != 56 {
            padded.append(0)
        }
        for shift in stride(from: 56, through: 0, by: -8) {
            padded.append(UInt8((bitLength >> UInt64(shift)) & 0xFF))
        }

        // §6.1.2 — process each 512-bit (64-byte) block.
        var w = [UInt32](repeating: 0, count: 80)
        for block in stride(from: 0, to: padded.count, by: 64) {
            for t in 0 ..< 16 {
                let i = block + t * 4
                w[t] =
                    (UInt32(padded[i]) << 24) | (UInt32(padded[i + 1]) << 16)
                    | (UInt32(padded[i + 2]) << 8) | UInt32(padded[i + 3])
            }
            for t in 16 ..< 80 {
                w[t] = rotateLeft(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], by: 1)
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            for t in 0 ..< 80 {
                let (f, k) = step(t, b, c, d)
                let temp = rotateLeft(a, by: 5) &+ f &+ e &+ k &+ w[t]
                e = d
                d = c
                c = rotateLeft(b, by: 30)
                b = a
                a = temp
            }
            h0 = h0 &+ a
            h1 = h1 &+ b
            h2 = h2 &+ c
            h3 = h3 &+ d
            h4 = h4 &+ e
        }

        return bigEndian(h0) + bigEndian(h1) + bigEndian(h2) + bigEndian(h3) + bigEndian(h4)
    }

    /// The §6.1.2 round function `f(t; b,c,d)` and constant `K(t)` for round `t`.
    private static func step(_ t: Int, _ b: UInt32, _ c: UInt32, _ d: UInt32) -> (UInt32, UInt32) {
        switch t {
            case 0 ..< 20:
                ((b & c) | (~b & d), 0x5A82_7999)
            case 20 ..< 40:
                (b ^ c ^ d, 0x6ED9_EBA1)
            case 40 ..< 60:
                ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC)
            default:
                (b ^ c ^ d, 0xCA62_C1D6)
        }
    }

    /// A 32-bit left rotation (FIPS 180-4 §3.2 `ROTL`).
    private static func rotateLeft(_ value: UInt32, by count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }

    /// `value` as four big-endian bytes (FIPS 180-4 §3.1 word-to-byte order).
    private static func bigEndian(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xFF), UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)
        ]
    }
}
