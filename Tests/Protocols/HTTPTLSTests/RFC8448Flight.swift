//
//  RFC8448Flight.swift
//  HTTPTLSTests
//
//  Splits an RFC 8448 server-flight fixture (EncryptedExtensions ∥ Certificate ∥
//  CertificateVerify ∥ Finished, §4 messages back to back) into its parts, using the engine's
//  own coalescer/parsers rather than magic offsets — the fixture identity needs the trace's
//  certificate DER and CertificateVerify signature as INPUTS, and slicing them via the codec
//  keeps the offsets honest.
//

@testable internal import HTTPTLS

/// A §3/§5 trace server flight, split into its §4 messages.
struct RFC8448Flight {
    /// The raw messages in flight order (header included).
    let messages: [TLSHandshakeCoalescer.Message]
    /// The leaf certificate DER carried in the Certificate message.
    let certificateDER: [UInt8]
    /// The CertificateVerify scheme + signature.
    let certificateVerify: TLSCertificateVerify

    /// Splits a trace flight; traps (test-only) on any shape surprise.
    init(_ flight: [UInt8]) throws {
        var coalescer = TLSHandshakeCoalescer(maximumMessageLength: 1 << 17)
        coalescer.feed(flight)
        var collected: [TLSHandshakeCoalescer.Message] = []
        while let message = try coalescer.next() {
            collected.append(message)
        }
        messages = collected
        var leaf: [UInt8] = []
        var verify = TLSCertificateVerify(scheme: .rsaPssRsaeSha256, signature: [])
        for message in collected {
            switch message.type {
                case .certificate:
                    // The trace's server Certificate reuses the client-cert parser shape
                    // (empty context, entries) — the §3/§5 chains carry no entry extensions.
                    leaf = try TLSCertificateCodec.parseClientCertificate(message).first ?? []
                case .certificateVerify:
                    verify = try TLSCertificateVerify.parse(message)
                default:
                    continue
            }
        }
        certificateDER = leaf
        certificateVerify = verify
    }
}
