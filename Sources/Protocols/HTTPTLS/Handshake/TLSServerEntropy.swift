//
//  TLSServerEntropy.swift
//  HTTPTLS
//
//  The randomness/ephemeral-key seam (RFC 8446 §4.1.3/§4.2.8/§4.6.1). The machine draws every
//  nondeterministic input through this protocol so the RFC 8448 gates can inject the traces'
//  PUBLISHED server ephemerals and randoms and compare output byte-exactly — the test-only
//  injection seam the Phase 3b brief names, cleanly separated from production randomness
//  (``TLSSystemEntropy``, the default, which never leaves swift-crypto/stdlib CSPRNGs).
//

/// The server's source of randomness and ephemeral key material.
public protocol TLSServerEntropy: Sendable {
    /// The 32-octet ServerHello `random` (§4.1.3).
    func serverRandom() -> [UInt8]

    /// A fresh raw private key for `group`'s key exchange (§4.2.8) — 32 octets for both
    /// implemented groups (X25519 raw scalar; P-256 raw representation).
    func ephemeralPrivateKey(for group: TLSNamedGroup) -> [UInt8]

    /// A fresh §4.6.1 `ticket_age_add` obfuscation value.
    func ticketAgeAdd() -> UInt32
}
