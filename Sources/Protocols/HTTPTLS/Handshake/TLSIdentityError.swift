//
//  TLSIdentityError.swift
//  HTTPTLS
//
//  The typed failure vocabulary of identity LOADING (Phase 3c). Every case is a startup-time
//  configuration fault: a misconfigured chain or key dies when the identity is constructed —
//  never per-handshake, where the peer would only see `internal_error` and the operator a
//  needle in a connection log. The one runtime case (`noCommonSignatureScheme`) surfaces
//  through the ``TLSIdentityProvider`` seam and funnels to §6.2 `internal_error` like every
//  other signing failure.
//

/// A failure loading or using a certificate identity (RFC 8446 §4.4.2/§4.4.3; RFC 5280).
public enum TLSIdentityError: Error, Sendable, Equatable {
    /// The certificate chain is empty — §4.4.2 requires at least the sender's leaf ("the
    /// sender's certificate MUST come in the first CertificateEntry").
    case emptyChain
    /// The certificate at `index` (0 = leaf) is not a decodable RFC 5280 `Certificate`.
    /// The label carries the parser's diagnostic.
    case undecodableCertificate(index: Int, String)
    /// The chain is not in §4.4.2 order: the certificate at `index` does not certify the one
    /// immediately preceding it (issuer/subject mismatch, or its signature over the
    /// predecessor does not verify). "Each following certificate SHOULD directly certify the
    /// one immediately preceding it" — this loader enforces it, at load time.
    case chainOutOfOrder(index: Int)
    /// The leaf certificate's SubjectPublicKeyInfo does not match the signing key — the
    /// CertificateVerify this identity would produce (§4.4.3) could never verify.
    case leafKeyMismatch
    /// The private-key PEM could not be decoded as any supported form — PKCS#8 (RFC 5958),
    /// SEC1 (RFC 5915) — or its DER contents are inconsistent. The label says which stage.
    case undecodablePrivateKey(String)
    /// The private key is RSA, which `HTTPTLS` deliberately cannot sign with (the recorded
    /// decision keeping `_CryptoExtras` out of this module): construct the identity with
    /// `HTTPTLSRSA.TLSRSAIdentitySigner` instead.
    case rsaKeyRequiresRSASigner
    /// The private key's algorithm (the PKCS#8 OID in the label) has no signer in this
    /// module — supported are P-256, P-384, P-521, and Ed25519 (§4.2.3's ECDSA/EdDSA rows).
    case unsupportedKeyAlgorithm(String)
    /// No offered §4.2.3 signature scheme is one this key can sign — the client's
    /// `signature_algorithms` ∩ configuration excluded the key's native scheme(s).
    case noCommonSignatureScheme(offered: [TLSSignatureScheme])
}
