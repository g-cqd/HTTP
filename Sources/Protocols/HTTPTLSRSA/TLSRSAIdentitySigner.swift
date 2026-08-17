//
//  TLSRSAIdentitySigner.swift
//  HTTPTLSRSA
//
//  RSA-PSS CertificateVerify signing (RFC 8446 §4.2.3 `rsa_pss_rsae_*`) — the signer that
//  makes RSA server identities (every `openssl req -newkey rsa:2048` dev identity) work with
//  the engine's ``TLSCertificateIdentity``. Lives OUTSIDE `HTTPTLS` because RSA needs
//  `_CryptoExtras` (the recorded 3b decision keeps that graph out of the engine).
//  `_CryptoExtras`' `.PSS` is exactly §4.2.3's profile: MGF1 with the digest's own hash and
//  a salt of the digest's length ("the length of the Salt MUST be equal to the length of the
//  output of the digest algorithm").
//

// swiftlint:disable sorted_imports - swift-format's OrderedImports sorts `_`-prefixed modules last
internal import Crypto
public import HTTPTLS
public import _CryptoExtras

// swiftlint:enable sorted_imports

/// Signs TLS 1.3 CertificateVerify content with an RSA key (RFC 8446 §4.2.3 RSA-PSS).
public struct TLSRSAIdentitySigner: TLSIdentitySigner {
    /// The `rsa_pss_rsae_*` schemes, the order in which candidates are honored is the
    /// CALLER's (server-preference — the ``TLSIdentitySigner`` contract).
    private static let schemes: Set<TLSSignatureScheme> = [
        .rsaPssRsaeSha256, .rsaPssRsaeSha384, .rsaPssRsaeSha512
    ]

    /// The RSA private key.
    private let key: _RSA.Signing.PrivateKey

    /// Wraps an already-loaded RSA key.
    public init(_ key: _RSA.Signing.PrivateKey) {
        self.key = key
    }

    /// Loads an unencrypted RSA private-key PEM — `RSA PRIVATE KEY` (PKCS#1, RFC 8017
    /// A.1.2) or `PRIVATE KEY` (PKCS#8, RFC 5958), the two forms the portable backbone's
    /// PEM intake accepts.
    public init(privateKeyPEM: String) throws(TLSIdentityError) {
        guard let key = try? _RSA.Signing.PrivateKey(pemRepresentation: privateKeyPEM) else {
            throw .undecodablePrivateKey("RSA PEM (PKCS#1 or PKCS#8, unencrypted)")
        }
        self.key = key
    }

    /// The key's DER SubjectPublicKeyInfo (RFC 5280 §4.1.2.7, `rsaEncryption`).
    public var subjectPublicKeyInfoDER: [UInt8] {
        [UInt8](key.publicKey.derRepresentation)
    }

    /// Signs under the first offered `rsa_pss_rsae_*` scheme (§4.2.3: the signature is the
    /// raw PSS block; the digest picks SHA-256/384/512 and thereby MGF1 hash + salt length).
    public func signature(
        over content: [UInt8], candidates: [TLSSignatureScheme]
    ) throws(TLSIdentityError) -> TLSSignature {
        guard let scheme = candidates.first(where: Self.schemes.contains) else {
            throw .noCommonSignatureScheme(offered: candidates)
        }
        guard let signature = try? sign(content, scheme: scheme) else {
            // RSA-PSS signing fails only on a backend fault (the key was already parsed);
            // fail closed through the same typed door as an impossible scheme.
            throw .noCommonSignatureScheme(offered: candidates)
        }
        return TLSSignature(scheme: scheme, bytes: signature)
    }

    /// The per-scheme digest dispatch (`signature(for:padding:)` hashes are digest-typed).
    private func sign(_ content: [UInt8], scheme: TLSSignatureScheme) throws -> [UInt8] {
        let signature: _RSA.Signing.RSASignature
        switch scheme {
            case .rsaPssRsaeSha384:
                signature = try key.signature(for: SHA384.hash(data: content), padding: .PSS)
            case .rsaPssRsaeSha512:
                signature = try key.signature(for: SHA512.hash(data: content), padding: .PSS)
            default:
                signature = try key.signature(for: SHA256.hash(data: content), padding: .PSS)
        }
        return [UInt8](signature.rawRepresentation)
    }
}
