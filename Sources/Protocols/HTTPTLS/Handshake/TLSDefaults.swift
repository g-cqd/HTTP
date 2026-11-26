//
//  TLSDefaults.swift
//  HTTPTLS
//
//  The negotiation defaults both connection roles start from (RFC 8446 §9.1 mandatory-to-implement
//  suites first).
//

/// Default TLS 1.3 negotiation preferences shared by client and server configurations.
enum TLSDefaults {
    /// All three §B.4 suites, AES-128-GCM first per §9.1's mandatory-to-implement.
    static let cipherSuites: [TLSCipherSuite] = [
        .aes128GcmSha256, .aes256GcmSha384, .chaCha20Poly1305Sha256
    ]
    /// The implemented §4.2.7 groups, X25519 first.
    static let groups: [TLSNamedGroup] = [.x25519, .secp256r1]
}
