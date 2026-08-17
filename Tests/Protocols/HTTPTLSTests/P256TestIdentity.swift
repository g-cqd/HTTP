//
//  P256TestIdentity.swift
//  HTTPTLSTests
//
//  A REAL signing identity for the non-trace end-to-end tests: a fresh P-256 key, a minimal
//  DER shell around its genuine SPKI, and live `ecdsa_secp256r1_sha256` signatures — so the
//  full handshake (including the client's verification path in ``HandshakeTestClient``)
//  exercises actual swift-crypto signing, not fixture playback.
//

import Crypto
internal import HTTPTLS

/// A server identity that genuinely signs with P-256 (scheme 0x0403).
struct P256TestIdentity: TLSIdentityProvider {
    /// The signing key.
    let key = P256.Signing.PrivateKey()

    /// One minimal DER certificate around the key's real SPKI.
    var certificateChainDER: [[UInt8]] {
        [
            TestCertificates.certificate(
                aroundSubjectPublicKeyInfo: [UInt8](key.publicKey.derRepresentation)
            )
        ]
    }

    /// Signs with ECDSA P-256/SHA-256 when offered.
    func signature(
        over content: [UInt8], algorithms: [TLSSignatureScheme]
    ) async throws -> TLSSignature {
        guard algorithms.contains(.ecdsaSecp256r1Sha256) else {
            throw TLSHandshakeError.signingFailed
        }
        let signature = try key.signature(for: content)
        return TLSSignature(
            scheme: .ecdsaSecp256r1Sha256, bytes: [UInt8](signature.derRepresentation)
        )
    }
}
