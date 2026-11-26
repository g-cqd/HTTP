//
//  TLSCertificateVerify.swift
//  HTTPTLS
//
//  RFC 8446 §4.4.3 — the CertificateVerify codec and its signed-content construction:
//
//      0x20 × 64 ∥ context string ∥ 0x00 ∥ Transcript-Hash(Handshake Context, Certificate)
//
//  with the context string binding the signer's role ("TLS 1.3, server CertificateVerify" /
//  "TLS 1.3, client CertificateVerify") so a signature can never be replayed across roles —
//  which is exactly what the wrong-context negative test proves.
//

/// A CertificateVerify message (RFC 8446 §4.4.3): the scheme and the signature octets.
struct TLSCertificateVerify: Sendable, Equatable {
    /// The §4.4.3 server context string.
    static let serverContext = "TLS 1.3, server CertificateVerify"
    /// The §4.4.3 client context string.
    static let clientContext = "TLS 1.3, client CertificateVerify"

    /// The signature scheme (§4.2.3) the signature was produced under.
    let scheme: TLSSignatureScheme
    /// The signature octets (scheme-defined encoding; ECDSA is DER `Ecdsa-Sig-Value`, §4.2.3).
    let signature: [UInt8]

    /// Builds the §4.4.3 content that is signed: padding, context, separator, transcript hash.
    static func signedContent(context: String, transcriptHash: [UInt8]) -> [UInt8] {
        var content = [UInt8](repeating: 0x20, count: 64)
        content.reserveCapacity(64 + context.utf8.count + 1 + transcriptHash.count)
        content.append(contentsOf: context.utf8)
        content.append(0)
        content.append(contentsOf: transcriptHash)
        return content
    }

    /// Encodes this CertificateVerify.
    func encoded() -> [UInt8] {
        TLSHandshakeBuilder.message(.certificateVerify) { message in
            message.u16(scheme.rawValue)
            message.vector16 { $0.raw(signature) }
        }
    }

    /// Parses a client CertificateVerify (§4.4.3).
    static func parse(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) -> Self {
        var reader = TLSHandshakeReader(message.body)
        let scheme = TLSSignatureScheme(rawValue: try reader.u16("signature scheme"))
        let signature = try reader.vector16("signature")
        guard !signature.isEmpty else {
            throw .malformed("signature empty")
        }
        try reader.expectEnd(of: "CertificateVerify")
        return Self(scheme: scheme, signature: [UInt8](signature))
    }

    /// What a peer's CertificateVerify must satisfy (§4.4.3): a scheme we offered, a verifier
    /// that supports it, and the role-bound signing context.
    struct PeerExpectation {
        let offered: [TLSSignatureScheme]
        let verifier: any TLSCertificateSignatureVerifier
        let context: String
    }

    /// §4.4.3: verifies a peer CertificateVerify against `expectation`, the transcript hash so
    /// far, and the leaf's SubjectPublicKeyInfo — then appends the message to `transcript`.
    static func verifyPeer(
        _ message: TLSHandshakeCoalescer.Message,
        expecting expectation: PeerExpectation,
        chain: [[UInt8]],
        transcript: inout TLSTranscriptHash?
    ) throws(TLSHandshakeError) {
        guard let transcriptHash = transcript?.currentHash, let leafDER = chain.first else {
            throw .internalError("CertificateVerify before Certificate")  // unreachable
        }
        let verify = try parse(message)
        guard expectation.offered.contains(verify.scheme) else {
            throw .illegalParameter("CertificateVerify scheme not offered")
        }
        guard expectation.verifier.supports(verify.scheme) else {
            throw .unverifiableCertificate(verify.scheme)  // fail closed
        }
        let spki = try DERPublicKeyLocator.subjectPublicKeyInfo(inCertificateDER: leafDER)
        let verified = expectation.verifier.verify(
            scheme: verify.scheme,
            signature: verify.signature,
            content: signedContent(context: expectation.context, transcriptHash: transcriptHash),
            subjectPublicKeyInfoDER: spki
        )
        guard verified else {
            throw .invalidCertificateVerify  // §4.4.3 — decrypt_error
        }
        transcript?.append(message.raw)
    }
}
