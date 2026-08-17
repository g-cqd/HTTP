//
//  TLSTrafficKeys.swift
//  HTTPTLS
//
//  RFC 8446 §7.3 — one direction's record-protection material, derived from a traffic secret:
//
//      write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
//      write_iv  = HKDF-Expand-Label(Secret, "iv",  "", iv_length)
//
//  The key stays in `SymmetricKey` for its whole life. The IV is the one piece that CANNOT: §5.3
//  XORs it with the record sequence number to form each nonce, and swift-crypto has no API to
//  XOR into a `SymmetricKey`, so the 12 IV octets are materialized ONCE here (the single unsafe
//  site) into fixed storage that the protector reuses for every nonce — never per record.
//

public import Crypto

/// One direction's §7.3 traffic keys: the AEAD key and the §5.3 per-record-nonce IV.
public struct TLSTrafficKeys: Sendable {
    /// The AEAD write/read key (`"key"` expansion, §7.3).
    let key: SymmetricKey
    /// The static nonce IV octets (`"iv"` expansion, §7.3), XORed with the sequence per §5.3.
    let ivBytes: [UInt8]

    /// Derives the key/IV pair for `suite` from a §7.1 traffic secret.
    public init(suite: TLSCipherSuite, trafficSecret: SymmetricKey) {
        let hash = suite.hash
        key = hash.expandLabel(trafficSecret, label: "key", context: [], length: suite.keyLength)
        let ivKey = hash.expandLabel(
            trafficSecret, label: "iv", context: [], length: suite.ivLength
        )
        // SAFETY: §5.3's per-record nonce is `iv XOR sequence`, which needs the IV as octets;
        // they are materialized exactly once per key installation, into storage owned by this
        // value, and swift-crypto offers no XOR-capable alternative to copying them out.
        ivBytes = unsafe ivKey.withUnsafeBytes { unsafe [UInt8]($0) }
    }
}
