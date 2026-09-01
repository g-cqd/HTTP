//
//  TLSCertificateSignatureVerifier.swift
//  HTTPTLS
//
//  The client-CertificateVerify verification seam (RFC 8446 §4.4.3). The default is
//  ``TLSECDSACertificateVerifier`` (swift-crypto core: ECDSA + Ed25519); deployments that must
//  accept RSA client certificates inject an `_CryptoExtras`-backed verifier here — Phase 3c
//  wires one alongside chain validation, keeping the RSA dependency OUT of HTTPTLS.
//

/// Verifies a peer CertificateVerify signature against a leaf's SubjectPublicKeyInfo (§4.4.3).
public protocol TLSCertificateSignatureVerifier: Sendable {
    /// Whether this verifier can check signatures under `scheme` — an unsupported scheme on a
    /// PRESENTED certificate is fatal (`unsupported_certificate`, fail closed).
    func supports(_ scheme: TLSSignatureScheme) -> Bool

    /// Returns whether `signature` verifies over `content` under `scheme` for the DER
    /// SubjectPublicKeyInfo. False is fatal (`decrypt_error`, §4.4.3).
    func verify(
        scheme: TLSSignatureScheme,
        signature: [UInt8],
        content: [UInt8],
        subjectPublicKeyInfoDER: [UInt8]
    ) -> Bool
}
