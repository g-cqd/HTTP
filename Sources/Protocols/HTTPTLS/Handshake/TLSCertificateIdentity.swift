//
//  TLSCertificateIdentity.swift
//  HTTPTLS
//
//  The production ``TLSIdentityProvider`` (Phase 3c): a validated X.509 chain plus a
//  ``TLSIdentitySigner``. Every §4.4.2 invariant is checked at LOAD time — leaf first, each
//  following certificate actually certifying its predecessor, the leaf's SPKI matching the
//  signing key — so a misconfigured deployment dies at startup with a typed
//  ``TLSIdentityError``, not per-handshake as an opaque `internal_error` alert. Parsing and
//  link-signature checks ride apple/swift-certificates; the chain is then kept as raw DER
//  (the §4.4.2 wire currency), so serving allocates nothing beyond what 3b already does.
//

internal import SwiftASN1
internal import X509

/// A server certificate identity: validated chain + signing key (RFC 8446 §4.4.2/§4.4.3).
public struct TLSCertificateIdentity: TLSSynchronousIdentityProvider {
    /// The certificate chain, leaf first, DER-encoded (§4.4.2 `CertificateEntry` order).
    public let certificateChainDER: [[UInt8]]
    /// The §4.4.3 signer for the leaf's key.
    private let signer: any TLSIdentitySigner

    /// Creates an identity from a DER chain (leaf first) and its signer, validating the
    /// §4.4.2 invariants: non-empty, decodable, ordered (each following certificate
    /// certifies the one immediately preceding it — issuer name AND signature), and the
    /// leaf's SubjectPublicKeyInfo equal to the signer's.
    public init(
        certificateChainDER: [[UInt8]], signer: any TLSIdentitySigner
    ) throws(TLSIdentityError) {
        guard !certificateChainDER.isEmpty else {
            throw .emptyChain  // §4.4.2: the sender's certificate MUST come first
        }
        let parsed = try Self.parse(certificateChainDER)
        try Self.validateOrder(parsed)
        try Self.validateLeafKey(leafDER: certificateChainDER[0], signer: signer)
        self.certificateChainDER = certificateChainDER
        self.signer = signer
    }

    /// Creates an identity from a PEM chain (RFC 7468 `CERTIFICATE` blocks, leaf first)
    /// and its signer.
    public init(
        certificateChainPEM: String, signer: any TLSIdentitySigner
    ) throws(TLSIdentityError) {
        try self.init(
            certificateChainDER: try Self.chainDER(fromPEM: certificateChainPEM),
            signer: signer
        )
    }

    /// Creates an identity from PEM texts.
    ///
    /// The portable-TLS `PEMIdentity` intake shape: the chain plus an unencrypted private
    /// key. The key must be one this module signs natively (P-256/P-384/P-521/Ed25519, via
    /// ``TLSPrivateKey``); an RSA key fails with
    /// ``TLSIdentityError/rsaKeyRequiresRSASigner`` — construct with
    /// `HTTPTLSRSA.TLSRSAIdentitySigner` instead.
    public init(
        certificateChainPEM: String, privateKeyPEM: String
    ) throws(TLSIdentityError) {
        try self.init(
            certificateChainPEM: certificateChainPEM,
            signer: try TLSPrivateKey(pemRepresentation: privateKeyPEM)
        )
    }

    /// Signs the §4.4.3 content by delegating to the signer (the ``TLSIdentityProvider``
    /// contract: `algorithms` is already intersected, server-preference order).
    public func signature(
        over content: [UInt8], algorithms: [TLSSignatureScheme]
    ) async throws -> TLSSignature {
        try signatureSynchronously(over: content, algorithms: algorithms)
    }

    /// The same delegation without suspension — a ``TLSIdentitySigner`` is synchronous by
    /// design, which is what lets this identity serve the synchronous drive (Phase 3d).
    public func signatureSynchronously(
        over content: [UInt8], algorithms: [TLSSignatureScheme]
    ) throws -> TLSSignature {
        try signer.signature(over: content, candidates: algorithms)
    }

    // MARK: load-time validation

    /// Decodes every chain element (RFC 5280 `Certificate`), naming the failing index.
    private static func parse(
        _ chain: [[UInt8]]
    ) throws(TLSIdentityError) -> [Certificate] {
        var parsed: [Certificate] = []
        parsed.reserveCapacity(chain.count)
        for (index, der) in chain.enumerated() {
            do {
                parsed.append(try Certificate(derEncoded: der))
            }
            catch {
                throw .undecodableCertificate(index: index, "\(error)")
            }
        }
        return parsed
    }

    /// §4.4.2 order: "Each following certificate SHOULD directly certify the one
    /// immediately preceding it" — enforced by issuer name AND link signature, so a chain
    /// pasted in the wrong order (or with a foreign intermediate) fails at load.
    private static func validateOrder(
        _ chain: [Certificate]
    ) throws(TLSIdentityError) {
        for index in 1 ..< chain.count {
            let issuer = chain[index]
            let subject = chain[index - 1]
            guard issuer.subject == subject.issuer,
                issuer.publicKey.isValidSignature(subject.signature, for: subject)
            else {
                throw .chainOutOfOrder(index: index)
            }
        }
    }

    /// The leaf's SubjectPublicKeyInfo must be the signer's key (§4.4.3 would otherwise
    /// produce a CertificateVerify no peer can validate).
    private static func validateLeafKey(
        leafDER: [UInt8], signer: any TLSIdentitySigner
    ) throws(TLSIdentityError) {
        let leafSPKI: [UInt8]
        do {
            leafSPKI = try DERPublicKeyLocator.subjectPublicKeyInfo(inCertificateDER: leafDER)
        }
        catch {
            throw .undecodableCertificate(index: 0, "SubjectPublicKeyInfo: \(error)")
        }
        guard leafSPKI == signer.subjectPublicKeyInfoDER else {
            throw .leafKeyMismatch
        }
    }

    /// RFC 7468: every `CERTIFICATE` block of a PEM bundle, in file order (= leaf first).
    private static func chainDER(
        fromPEM pem: String
    ) throws(TLSIdentityError) -> [[UInt8]] {
        guard let documents = try? PEMDocument.parseMultiple(pemString: pem) else {
            throw .undecodableCertificate(index: 0, "not a PEM bundle (RFC 7468)")
        }
        let chain = documents.filter { $0.discriminator == "CERTIFICATE" }
        guard !chain.isEmpty else {
            throw .emptyChain
        }
        return chain.map(\.derBytes)
    }
}
