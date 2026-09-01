//
//  TLSRSACertificateVerifier.swift
//  HTTPTLSRSA
//
//  RSA-PSS client-CertificateVerify verification (RFC 8446 §4.4.3) for deployments that must
//  accept RSA client certificates — injected as
//  ``TLSServerConfiguration/certificateVerifier``. Composes over a fallback (the engine's
//  ECDSA/Ed25519 default) so swapping it in WIDENS what clients can present instead of
//  trading ECDSA away. Same module rationale as the signer: RSA rides `_CryptoExtras`,
//  which stays out of `HTTPTLS`.
//

// swiftlint:disable sorted_imports - swift-format's OrderedImports sorts `_`-prefixed modules last
internal import Crypto
public import HTTPTLS
internal import _CryptoExtras

// swiftlint:enable sorted_imports

/// Verifies `rsa_pss_rsae_*` CertificateVerify signatures, delegating other schemes
/// (RFC 8446 §4.4.3).
public struct TLSRSACertificateVerifier: TLSCertificateSignatureVerifier {
    /// The `rsa_pss_rsae_*` schemes this verifier owns.
    private static let schemes: Set<TLSSignatureScheme> = [
        .rsaPssRsaeSha256, .rsaPssRsaeSha384, .rsaPssRsaeSha512
    ]

    /// The verifier consulted for every non-RSA scheme.
    private let fallback: any TLSCertificateSignatureVerifier

    /// Creates the verifier; the default fallback keeps the engine's ECDSA P-256/384/521 +
    /// Ed25519 coverage intact.
    public init(
        fallback: any TLSCertificateSignatureVerifier = TLSECDSACertificateVerifier()
    ) {
        self.fallback = fallback
    }

    /// RSA-PSS or whatever the fallback supports.
    public func supports(_ scheme: TLSSignatureScheme) -> Bool {
        Self.schemes.contains(scheme) || fallback.supports(scheme)
    }

    /// §4.4.3: RSA-PSS verification against the leaf's SubjectPublicKeyInfo (the digest
    /// picks the hash, MGF1 hash, and salt length — the §4.2.3 PSS profile); non-RSA
    /// schemes delegate.
    public func verify(
        scheme: TLSSignatureScheme,
        signature: [UInt8],
        content: [UInt8],
        subjectPublicKeyInfoDER: [UInt8]
    ) -> Bool {
        guard Self.schemes.contains(scheme) else {
            return fallback.verify(
                scheme: scheme,
                signature: signature,
                content: content,
                subjectPublicKeyInfoDER: subjectPublicKeyInfoDER
            )
        }
        guard
            let key = try? _RSA.Signing.PublicKey(derRepresentation: subjectPublicKeyInfoDER)
        else {
            return false  // fail closed: an SPKI that is not a usable RSA key
        }
        let pss = _RSA.Signing.RSASignature(rawRepresentation: signature)
        switch scheme {
            case .rsaPssRsaeSha384:
                return key.isValidSignature(pss, for: SHA384.hash(data: content), padding: .PSS)
            case .rsaPssRsaeSha512:
                return key.isValidSignature(pss, for: SHA512.hash(data: content), padding: .PSS)
            default:
                return key.isValidSignature(pss, for: SHA256.hash(data: content), padding: .PSS)
        }
    }
}
