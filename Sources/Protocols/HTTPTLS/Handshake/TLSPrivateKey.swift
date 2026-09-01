//
//  TLSPrivateKey.swift
//  HTTPTLS
//
//  The swift-crypto-native signing keys (Phase 3c): ECDSA P-256/384/521 and Ed25519 — every
//  §4.2.3 CertificateVerify family this module can sign without `_CryptoExtras` (RSA-PSS is
//  `HTTPTLSRSA`'s). PEM intake dispatches on the RFC 7468 label and, for PKCS#8, on the
//  RFC 5958 algorithm OID — so an RSA key fails with a typed pointer at the RSA module
//  instead of a generic decode error. Each curve pins its §4.2.3 scheme (the hash is bound
//  to the curve: P-256→SHA-256, P-384→SHA-384, P-521→SHA-512) and Ed25519 signs pure.
//

public import Crypto
internal import SwiftASN1

/// A private key HTTPTLS signs CertificateVerify with natively (RFC 8446 §4.2.3).
public enum TLSPrivateKey: Sendable, TLSIdentitySigner {
    /// An ECDSA P-256 key — signs `ecdsa_secp256r1_sha256` (§4.2.3).
    case p256(P256.Signing.PrivateKey)
    /// An ECDSA P-384 key — signs `ecdsa_secp384r1_sha384` (§4.2.3).
    case p384(P384.Signing.PrivateKey)
    /// An ECDSA P-521 key — signs `ecdsa_secp521r1_sha512` (§4.2.3).
    case p521(P521.Signing.PrivateKey)
    /// An Ed25519 key — signs `ed25519` (§4.2.3, RFC 8032 pure).
    case ed25519(Curve25519.Signing.PrivateKey)

    /// Loads a PEM private key (RFC 7468): a `PRIVATE KEY` (PKCS#8, RFC 5958) or
    /// `EC PRIVATE KEY` (SEC1, RFC 5915) block. `RSA PRIVATE KEY` — and an RSA-bearing
    /// PKCS#8 — fail with ``TLSIdentityError/rsaKeyRequiresRSASigner``.
    public init(pemRepresentation: String) throws(TLSIdentityError) {
        guard let document = try? PEMDocument(pemString: pemRepresentation) else {
            throw .undecodablePrivateKey("not a single PEM block (RFC 7468)")
        }
        switch document.discriminator {
            case "PRIVATE KEY":
                self = try Self.fromPKCS8(document.derBytes)
            case "EC PRIVATE KEY":
                self = try Self.fromSEC1(document.derBytes)
            case "RSA PRIVATE KEY":
                throw .rsaKeyRequiresRSASigner  // PKCS#1 (RFC 8017 A.1.2)
            default:
                throw .undecodablePrivateKey(
                    "PEM label \(document.discriminator) is not a private key"
                )
        }
    }

    // MARK: RFC 5958 / RFC 5915 intake

    /// `id-ecPublicKey` (RFC 5480 §2.1.1).
    private static let ecPublicKeyOID: ASN1ObjectIdentifier = [1, 2, 840, 10_045, 2, 1]
    /// `id-Ed25519` (RFC 8410 §3).
    static let ed25519OID: ASN1ObjectIdentifier = [1, 3, 101, 112]
    /// `rsaEncryption` (RFC 8017 A.1).
    private static let rsaEncryptionOID: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 1, 1]
    /// `secp256r1` / `secp384r1` / `secp521r1` (RFC 5480 §2.1.1.1).
    private static let p256OID: ASN1ObjectIdentifier = [1, 2, 840, 10_045, 3, 1, 7]
    private static let p384OID: ASN1ObjectIdentifier = [1, 3, 132, 0, 34]
    private static let p521OID: ASN1ObjectIdentifier = [1, 3, 132, 0, 35]

    /// RFC 5958 §2 `OneAsymmetricKey`: version, `AlgorithmIdentifier`, key octets — the
    /// algorithm OID picks the swift-crypto type (or names the unsupported algorithm).
    private static func fromPKCS8(_ der: [UInt8]) throws(TLSIdentityError) -> Self {
        let contents: (algorithm: ASN1ObjectIdentifier, curve: ASN1ObjectIdentifier?, key: [UInt8])
        do {
            contents = try readOneAsymmetricKey(der)
        }
        catch {
            throw .undecodablePrivateKey("PKCS#8 structure: \(error)")
        }
        switch contents.algorithm {
            case ecPublicKeyOID:
                // swift-crypto's `derRepresentation` intake reads PKCS#8 natively; the
                // curve OID (RFC 5480 §2.1.1.1 `namedCurve`) picks the concrete type.
                return try fromECAlgorithm(curve: contents.curve, der: der)
            case ed25519OID:
                return try fromEd25519KeyOctets(contents.key)
            case rsaEncryptionOID:
                throw .rsaKeyRequiresRSASigner
            default:
                throw .unsupportedKeyAlgorithm(String(describing: contents.algorithm))
        }
    }

    /// The RFC 5958 §2 walk itself (untyped SwiftASN1 errors; the caller wraps them).
    private static func readOneAsymmetricKey(
        _ der: [UInt8]
    ) throws -> (algorithm: ASN1ObjectIdentifier, curve: ASN1ObjectIdentifier?, key: [UInt8]) {
        try DER.sequence(try DER.parse(der), identifier: .sequence) { nodes in
            _ = try Int(derEncoded: &nodes)  // version (v1 = 0, v2 = 1 — both readable)
            guard let algorithmNode = nodes.next() else {
                throw ASN1Error.invalidASN1Object(reason: "missing AlgorithmIdentifier")
            }
            let identity = try DER.sequence(
                algorithmNode, identifier: .sequence
            ) { algorithm -> (ASN1ObjectIdentifier, ASN1ObjectIdentifier?) in
                let oid = try ASN1ObjectIdentifier(derEncoded: &algorithm)
                // RFC 5480 §2.1.1: for id-ecPublicKey the parameters are the namedCurve OID.
                let curve = algorithm.next().flatMap { try? ASN1ObjectIdentifier(derEncoded: $0) }
                return (oid, curve)
            }
            guard let keyNode = nodes.next() else {
                throw ASN1Error.invalidASN1Object(reason: "missing privateKey octets")
            }
            let key = try ASN1OctetString(derEncoded: keyNode)
            return (identity.0, identity.1, [UInt8](key.bytes))
        }
    }

    /// RFC 5480 §2.1.1.1: the named curve picks P-256/P-384/P-521.
    private static func fromECAlgorithm(
        curve: ASN1ObjectIdentifier?, der: [UInt8]
    ) throws(TLSIdentityError) -> Self {
        switch curve {
            case p256OID:
                guard let key = try? P256.Signing.PrivateKey(derRepresentation: der) else {
                    throw .undecodablePrivateKey("P-256 PKCS#8 key octets")
                }
                return .p256(key)
            case p384OID:
                guard let key = try? P384.Signing.PrivateKey(derRepresentation: der) else {
                    throw .undecodablePrivateKey("P-384 PKCS#8 key octets")
                }
                return .p384(key)
            case p521OID:
                guard let key = try? P521.Signing.PrivateKey(derRepresentation: der) else {
                    throw .undecodablePrivateKey("P-521 PKCS#8 key octets")
                }
                return .p521(key)
            default:
                throw .unsupportedKeyAlgorithm(
                    "EC namedCurve \(curve.map(String.init(describing:)) ?? "absent")"
                )
        }
    }

    /// RFC 8410 §7: PKCS#8 `privateKey` wraps `CurvePrivateKey ::= OCTET STRING` — one more
    /// DER layer around the 32 raw Ed25519 octets.
    private static func fromEd25519KeyOctets(
        _ octets: [UInt8]
    ) throws(TLSIdentityError) -> Self {
        guard let inner = try? ASN1OctetString(derEncoded: octets),
            let key = try? Curve25519.Signing.PrivateKey(
                rawRepresentation: [UInt8](inner.bytes)
            )
        else {
            throw .undecodablePrivateKey("Ed25519 CurvePrivateKey octets (RFC 8410 §7)")
        }
        return .ed25519(key)
    }

    /// RFC 5915 `ECPrivateKey` — swift-crypto reads SEC1 DER directly; the curve is implied
    /// by the key size, so the three candidates are simply tried in turn.
    private static func fromSEC1(_ der: [UInt8]) throws(TLSIdentityError) -> Self {
        if let key = try? P256.Signing.PrivateKey(derRepresentation: der) {
            return .p256(key)
        }
        if let key = try? P384.Signing.PrivateKey(derRepresentation: der) {
            return .p384(key)
        }
        if let key = try? P521.Signing.PrivateKey(derRepresentation: der) {
            return .p521(key)
        }
        throw .undecodablePrivateKey("SEC1 ECPrivateKey (RFC 5915) on any supported curve")
    }

    // MARK: TLSIdentitySigner

    /// The one §4.2.3 scheme this key signs — curve-bound hash for ECDSA, pure for Ed25519.
    public var nativeScheme: TLSSignatureScheme {
        switch self {
            case .p256:
                .ecdsaSecp256r1Sha256
            case .p384:
                .ecdsaSecp384r1Sha384
            case .p521:
                .ecdsaSecp521r1Sha512
            case .ed25519:
                .ed25519
        }
    }

    /// The DER SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) — swift-crypto's SPKI for the EC
    /// curves; RFC 8410 §4's fixed shell built around the raw key for Ed25519.
    public var subjectPublicKeyInfoDER: [UInt8] {
        switch self {
            case .p256(let key):
                [UInt8](key.publicKey.derRepresentation)
            case .p384(let key):
                [UInt8](key.publicKey.derRepresentation)
            case .p521(let key):
                [UInt8](key.publicKey.derRepresentation)
            case .ed25519(let key):
                Self.ed25519SubjectPublicKeyInfo(key.publicKey)
        }
    }

    /// Signs under this key's native scheme when offered (§4.2.3 wire encodings: DER
    /// `Ecdsa-Sig-Value` for ECDSA, the 64 raw octets for Ed25519).
    public func signature(
        over content: [UInt8], candidates: [TLSSignatureScheme]
    ) throws(TLSIdentityError) -> TLSSignature {
        guard candidates.contains(nativeScheme) else {
            throw .noCommonSignatureScheme(offered: candidates)
        }
        let bytes: [UInt8]
        do {
            switch self {
                case .p256(let key):
                    bytes = [UInt8](try key.signature(for: content).derRepresentation)
                case .p384(let key):
                    bytes = [UInt8](try key.signature(for: content).derRepresentation)
                case .p521(let key):
                    bytes = [UInt8](try key.signature(for: content).derRepresentation)
                case .ed25519(let key):
                    bytes = [UInt8](try key.signature(for: content))
            }
        }
        catch {
            // swift-crypto signing over well-formed inputs does not fail in practice; a
            // throw here is an entropy/backend fault — surfaced as no-scheme-workable.
            throw .noCommonSignatureScheme(offered: candidates)
        }
        return TLSSignature(scheme: nativeScheme, bytes: bytes)
    }

    /// RFC 8410 §4: `SEQUENCE { SEQUENCE { id-Ed25519 }, BIT STRING key }` — swift-crypto
    /// exposes no SPKI serialization for Curve25519, so the 12-octet shell is built here.
    private static func ed25519SubjectPublicKeyInfo(
        _ key: Curve25519.Signing.PublicKey
    ) -> [UInt8] {
        var serializer = DER.Serializer()
        do {
            try serializer.appendConstructedNode(identifier: .sequence) { spki in
                try spki.appendConstructedNode(identifier: .sequence) { algorithm in
                    try algorithm.serialize(ed25519OID)
                }
                try spki.serialize(ASN1BitString(bytes: ArraySlice(key.rawRepresentation)))
            }
        }
        catch {
            // Unreachable: serializing two fixed, well-formed nodes cannot fail.
            return []
        }
        return serializer.serializedBytes
    }
}
