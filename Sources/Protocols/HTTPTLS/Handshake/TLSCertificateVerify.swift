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
}
