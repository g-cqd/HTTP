//
//  HMACSHA256.swift
//  HTTPCore
//
//  RFC 2104 — HMAC, instantiated with FIPS 180-4 SHA-256 (``SHA256``): the keyed tag that makes a session
//  cookie tamper-proof and the building block of ``HKDF``. Pure Swift so the package needs no CryptoKit
//  (Apple-only) and stays cross-platform. `HMAC(K, m) = H((K' ⊕ opad) ‖ H((K' ⊕ ipad) ‖ m))`, where `K'`
//  is the key zero-padded to the 64-byte block size (or its hash when longer). Verification compares in
//  constant time so a forged tag cannot be discovered byte-by-byte through timing. Public so the auth /
//  session layers above share one primitive.
//

/// RFC 2104 HMAC over ``SHA256`` — a keyed integrity tag (and the PRF inside ``HKDF``).
public enum HMACSHA256 {
    /// The SHA-256 block size in bytes (RFC 2104 `B`).
    private static let blockSize = 64

    /// The 32-byte HMAC-SHA256 of `message` under `key` (RFC 2104).
    public static func authenticationCode(key: [UInt8], message: [UInt8]) -> [UInt8] {
        // RFC 2104 — derive `K'`: hash an over-long key, then zero-pad to the block size.
        var normalized = key.count > blockSize ? SHA256.hash(key) : key
        if normalized.count < blockSize {
            normalized += [UInt8](repeating: 0, count: blockSize - normalized.count)
        }
        let innerPad = normalized.map { $0 ^ 0x36 }
        let outerPad = normalized.map { $0 ^ 0x5C }
        let inner = SHA256.hash(innerPad + message)
        return SHA256.hash(outerPad + inner)
    }

    /// Whether `lhs` and `rhs` are equal, comparing in constant time (no early exit) so a near-miss tag
    /// cannot be refined from the comparison's timing (RFC 2104 verification).
    public static func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }
        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }
}
