//
//  HKDF.swift
//  HTTPCore
//
//  RFC 5869 — HKDF, the HMAC-based extract-and-expand key derivation function, over ``HMACSHA256``.
//  Extract condenses input keying material (with an optional salt) into a fixed-length pseudorandom key;
//  expand stretches that key, bound to a context `info` string, into as many output octets as needed.
//  Pure Swift (no CryptoKit), so a consumer can derive independent sub-keys from one secret — e.g. a
//  session-signing key and an encryption key from a single master key — without pulling in a crypto
//  dependency. Trap-free: an out-of-range length returns `nil`.
//

/// RFC 5869 HKDF (extract-and-expand) instantiated with HMAC-SHA256.
public enum HKDF {
    /// The SHA-256 output length in octets (RFC 5869 `HashLen`).
    private static let hashLength = 32

    /// HKDF-Extract (RFC 5869 §2.2): condense `inputKeyMaterial` and an optional `salt` into a 32-octet
    /// pseudorandom key.
    ///
    /// An empty salt is treated as `HashLen` zero octets.
    public static func extract(salt: [UInt8] = [], inputKeyMaterial: [UInt8]) -> [UInt8] {
        let effectiveSalt = salt.isEmpty ? [UInt8](repeating: 0, count: hashLength) : salt
        return HMACSHA256.authenticationCode(key: effectiveSalt, message: inputKeyMaterial)
    }

    /// HKDF-Expand (RFC 5869 §2.3): `length` output octets from a pseudorandom key, bound to `info`.
    ///
    /// Returns `nil` for a `length` outside `0...255*HashLen` (the RFC's maximum), never trapping.
    public static func expand(
        pseudoRandomKey: [UInt8], info: [UInt8] = [], length: Int
    ) -> [UInt8]? {
        guard length >= 0, length <= 255 * hashLength else {
            return nil
        }
        var output: [UInt8] = []
        var block: [UInt8] = []
        var counter: UInt8 = 1
        while output.count < length {
            // T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i); the length guard bounds i to ≤255 so the counter is safe.
            block = HMACSHA256.authenticationCode(
                key: pseudoRandomKey, message: block + info + [counter]
            )
            output += block
            counter &+= 1
        }
        return Array(output.prefix(length))
    }

    /// HKDF (RFC 5869 §2): derive `length` octets from `inputKeyMaterial`, an optional `salt`, and a
    /// context `info` — extract-then-expand.
    ///
    /// Returns `nil` for an out-of-range `length`.
    public static func derive(
        inputKeyMaterial: [UInt8], salt: [UInt8] = [], info: [UInt8] = [], length: Int
    ) -> [UInt8]? {
        expand(
            pseudoRandomKey: extract(salt: salt, inputKeyMaterial: inputKeyMaterial),
            info: info,
            length: length
        )
    }
}
