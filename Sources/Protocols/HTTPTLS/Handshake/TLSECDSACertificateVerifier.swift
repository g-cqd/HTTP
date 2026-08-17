//
//  TLSECDSACertificateVerifier.swift
//  HTTPTLS
//
//  The default ``TLSCertificateSignatureVerifier``: what swift-crypto's CORE module can verify
//  — ECDSA P-256/P-384/P-521 (DER `Ecdsa-Sig-Value`, hash fixed by the scheme per RFC 8446
//  §4.2.3) and Ed25519. RSA-PSS verification would need `_CryptoExtras`, which HTTPTLS
//  deliberately does not depend on (the recorded Phase 3b decision — HTTPAuth already carries
//  it; RSA client certificates ride an injected verifier instead).
//

internal import Crypto

/// The default verifier: ECDSA P-256/384/521 + Ed25519, all swift-crypto core.
public struct TLSECDSACertificateVerifier: TLSCertificateSignatureVerifier {
    /// Creates the default verifier.
    public init() {
        // Stateless — swift-crypto key objects are built per verification.
    }

    /// The swift-crypto-core verifiable schemes.
    public func supports(_ scheme: TLSSignatureScheme) -> Bool {
        scheme == .ecdsaSecp256r1Sha256 || scheme == .ecdsaSecp384r1Sha384
            || scheme == .ecdsaSecp521r1Sha512 || scheme == .ed25519
    }

    /// Dispatches to the scheme's swift-crypto verifier; any decoding failure is simply an
    /// invalid signature (false — the §4.4.3 outcome does not distinguish).
    public func verify(
        scheme: TLSSignatureScheme,
        signature: [UInt8],
        content: [UInt8],
        subjectPublicKeyInfoDER: [UInt8]
    ) -> Bool {
        switch scheme {
            case .ecdsaSecp256r1Sha256:
                guard
                    let key = try? P256.Signing.PublicKey(
                        derRepresentation: subjectPublicKeyInfoDER
                    ),
                    let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature)
                else {
                    return false
                }
                return key.isValidSignature(sig, for: content)
            case .ecdsaSecp384r1Sha384:
                guard
                    let key = try? P384.Signing.PublicKey(
                        derRepresentation: subjectPublicKeyInfoDER
                    ),
                    let sig = try? P384.Signing.ECDSASignature(derRepresentation: signature)
                else {
                    return false
                }
                return key.isValidSignature(sig, for: content)
            case .ecdsaSecp521r1Sha512:
                guard
                    let key = try? P521.Signing.PublicKey(
                        derRepresentation: subjectPublicKeyInfoDER
                    ),
                    let sig = try? P521.Signing.ECDSASignature(derRepresentation: signature)
                else {
                    return false
                }
                return key.isValidSignature(sig, for: content)
            case .ed25519:
                guard
                    let raw = try? DERPublicKeyLocator.rawSubjectPublicKey(
                        inSubjectPublicKeyInfoDER: subjectPublicKeyInfoDER
                    ),
                    let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw)
                else {
                    return false
                }
                return key.isValidSignature(signature, for: content)
            default:
                return false  // unreachable behind supports(_:) — fail closed anyway
        }
    }
}
