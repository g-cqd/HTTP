//
//  SHA256.swift
//  HTTPServer
//
//  FIPS 180-4 §6.2 — SHA-256, the hash under the session cookie's HMAC (``HMACSHA256``). A pure-Swift
//  implementation so signed-cookie integrity needs no CryptoKit (Apple-only) and the server stays
//  cross-platform; it runs over a short cookie id per request, where throughput is irrelevant. The
//  computation is data-independent (no secret-dependent branch or index), so it does not leak the key
//  through timing.
//

/// FIPS 180-4 §6.2 SHA-256 — a 256-bit digest, used only as the hash inside ``HMACSHA256``.
enum SHA256 {
    /// The 32-byte SHA-256 digest of `message` (FIPS 180-4 §6.2.2).
    static func hash(_ message: [UInt8]) -> [UInt8] {
        // §5.3.3 — the initial hash value.
        var h: [UInt32] = [
            0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
            0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
        ]

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

        // §6.2.2 — process each 512-bit (64-byte) block.
        var w = [UInt32](repeating: 0, count: 64)
        for block in stride(from: 0, to: padded.count, by: 64) {
            for t in 0 ..< 16 {
                let i = block + t * 4
                w[t] =
                    (UInt32(padded[i]) << 24) | (UInt32(padded[i + 1]) << 16)
                    | (UInt32(padded[i + 2]) << 8) | UInt32(padded[i + 3])
            }
            for t in 16 ..< 64 {
                let s0 = rotateRight(w[t - 15], 7) ^ rotateRight(w[t - 15], 18) ^ (w[t - 15] >> 3)
                let s1 = rotateRight(w[t - 2], 17) ^ rotateRight(w[t - 2], 19) ^ (w[t - 2] >> 10)
                w[t] = w[t - 16] &+ s0 &+ w[t - 7] &+ s1
            }
            compress(&h, w)
        }

        return h.flatMap(bigEndian)
    }

    /// The §6.2.2 step-3 compression of message schedule `w` into the running hash `h`.
    private static func compress(_ h: inout [UInt32], _ w: [UInt32]) {
        var a = h[0]
        var b = h[1]
        var c = h[2]
        var d = h[3]
        var e = h[4]
        var f = h[5]
        var g = h[6]
        var hh = h[7]
        for t in 0 ..< 64 {
            let big1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
            let ch = (e & f) ^ (~e & g)
            let temp1 = hh &+ big1 &+ ch &+ constants[t] &+ w[t]
            let big0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
            let maj = (a & b) ^ (a & c) ^ (b & c)
            let temp2 = big0 &+ maj
            hh = g
            g = f
            f = e
            e = d &+ temp1
            d = c
            c = b
            b = a
            a = temp1 &+ temp2
        }
        h[0] &+= a
        h[1] &+= b
        h[2] &+= c
        h[3] &+= d
        h[4] &+= e
        h[5] &+= f
        h[6] &+= g
        h[7] &+= hh
    }

    /// The §4.2.2 round constants `K(0..63)` — the first 32 bits of the cube roots of the first 64 primes.
    private static let constants: [UInt32] = [
        0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5, 0x3956_C25B, 0x59F1_11F1, 0x923F_82A4,
        0xAB1C_5ED5, 0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3, 0x72BE_5D74, 0x80DE_B1FE,
        0x9BDC_06A7, 0xC19B_F174, 0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC, 0x2DE9_2C6F,
        0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA, 0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7,
        0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967, 0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC,
        0x5338_0D13, 0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85, 0xA2BF_E8A1, 0xA81A_664B,
        0xC24B_8B70, 0xC76C_51A3, 0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070, 0x19A4_C116,
        0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5, 0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3,
        0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208, 0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7,
        0xC671_78F2
    ]

    /// A 32-bit right rotation (FIPS 180-4 §3.2 `ROTR`).
    private static func rotateRight(_ value: UInt32, _ count: UInt32) -> UInt32 {
        (value >> count) | (value << (32 - count))
    }

    /// `value` as four big-endian bytes (FIPS 180-4 §3.1 word-to-byte order).
    private static func bigEndian(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xFF), UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)
        ]
    }
}
