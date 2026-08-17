//
//  TLSIdentitySigner.swift
//  HTTPTLS
//
//  The private-key half of a certificate identity (Phase 3c): what
//  ``TLSCertificateIdentity`` delegates §4.4.3 signing to, split from the chain so the key
//  algorithm is pluggable — ``TLSPrivateKey`` covers what swift-crypto signs natively
//  (ECDSA P-256/384/521, Ed25519), and `HTTPTLSRSA` adds RSA-PSS without `_CryptoExtras`
//  ever entering this module (the recorded 3b decision). Synchronous by design: a local key
//  signs without suspension, and a hardware- or remote-backed signer should implement the
//  async ``TLSIdentityProvider`` seam directly instead.
//

/// Signs TLS 1.3 CertificateVerify content with one private key (RFC 8446 §4.4.3).
public protocol TLSIdentitySigner: Sendable {
    /// The key's DER SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) — checked against the leaf
    /// certificate at identity load time (``TLSIdentityError/leafKeyMismatch``).
    var subjectPublicKeyInfoDER: [UInt8] { get }

    /// Signs `content` under the first scheme in `candidates` this key supports (§4.2.3
    /// candidates arrive pre-intersected, server-preference order — the ``TLSIdentityProvider``
    /// contract). Throws ``TLSIdentityError/noCommonSignatureScheme(offered:)`` when none fits.
    func signature(
        over content: [UInt8], candidates: [TLSSignatureScheme]
    ) throws(TLSIdentityError) -> TLSSignature
}
