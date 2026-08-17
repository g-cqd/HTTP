//
//  TLSSignatureScheme.swift
//  HTTPTLS
//
//  RFC 8446 §4.2.3 — the `SignatureScheme` registry. A struct over the raw value: a peer may
//  offer schemes this server does not know (skipped during negotiation, never a parse failure).
//  Verification capability lives with ``TLSCertificateSignatureVerifier``; signing capability
//  lives with ``TLSIdentityProvider`` — this type only names schemes and classifies the ones
//  RFC 8446 forbids for TLS 1.3 CertificateVerify (the legacy rsa_pkcs1/SHA-1 rows, §4.4.3).
//

/// A TLS signature scheme (RFC 8446 §4.2.3; unknown values are preserved for negotiation).
public struct TLSSignatureScheme: RawRepresentable, Sendable, Equatable, Hashable {
    /// The wire value (§4.2.3's `SignatureScheme`).
    public let rawValue: UInt16

    /// Wraps a raw signature-scheme value (unknown values survive parsing per §4.1.2).
    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// `rsa_pkcs1_sha256(0x0401)` — certificate signatures only, never CertificateVerify (§4.4.3).
    public static let rsaPkcs1Sha256 = Self(rawValue: 0x0401)
    /// `ecdsa_secp256r1_sha256(0x0403)` (§4.2.3).
    public static let ecdsaSecp256r1Sha256 = Self(rawValue: 0x0403)
    /// `rsa_pkcs1_sha384(0x0501)` — certificate signatures only (§4.4.3).
    public static let rsaPkcs1Sha384 = Self(rawValue: 0x0501)
    /// `ecdsa_secp384r1_sha384(0x0503)` (§4.2.3).
    public static let ecdsaSecp384r1Sha384 = Self(rawValue: 0x0503)
    /// `rsa_pkcs1_sha512(0x0601)` — certificate signatures only (§4.4.3).
    public static let rsaPkcs1Sha512 = Self(rawValue: 0x0601)
    /// `ecdsa_secp521r1_sha512(0x0603)` (§4.2.3).
    public static let ecdsaSecp521r1Sha512 = Self(rawValue: 0x0603)
    /// `rsa_pss_rsae_sha256(0x0804)` (§4.2.3).
    public static let rsaPssRsaeSha256 = Self(rawValue: 0x0804)
    /// `rsa_pss_rsae_sha384(0x0805)` (§4.2.3).
    public static let rsaPssRsaeSha384 = Self(rawValue: 0x0805)
    /// `rsa_pss_rsae_sha512(0x0806)` (§4.2.3).
    public static let rsaPssRsaeSha512 = Self(rawValue: 0x0806)
    /// `ed25519(0x0807)` (§4.2.3).
    public static let ed25519 = Self(rawValue: 0x0807)
    /// `ed448(0x0808)` (§4.2.3) — recognized, not verifiable in-module.
    public static let ed448 = Self(rawValue: 0x0808)
    /// `rsa_pss_pss_sha256(0x0809)` (§4.2.3).
    public static let rsaPssPssSha256 = Self(rawValue: 0x0809)

    /// Whether RFC 8446 permits this scheme in a TLS 1.3 CertificateVerify.
    ///
    /// §4.4.3 forbids the `rsa_pkcs1_*` rows and anything SHA-1-based ("RSASSA-PKCS1-v1_5
    /// algorithms ... are not defined for use in signed TLS handshake messages"); they may
    /// appear in `signature_algorithms` solely to describe certificate signatures.
    public var isPermittedInCertificateVerify: Bool {
        switch self {
            case .rsaPkcs1Sha256, .rsaPkcs1Sha384, .rsaPkcs1Sha512:
                false
            default:
                // SHA-1 legacy rows (0x0201/0x0203) and unknown values are excluded by never
                // being negotiated: negotiation intersects with the configured server list.
                rawValue > 0x0400
        }
    }
}
