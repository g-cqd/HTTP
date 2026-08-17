//
//  TLSNegotiatedParameters.swift
//  HTTPTLS
//
//  What one completed RFC 8446 handshake settled on — surfaced with
//  ``TLSServerEvent/handshakeCompleted(_:)`` and kept on the connection. The client
//  certificate chain rides here as raw DER (leaf first) for Phase 3c's swift-certificates
//  chain validation; Phase 3b has already verified the leaf's CertificateVerify signature
//  (§4.4.3) when the chain is non-empty.
//

/// The outcome of one TLS 1.3 server handshake (RFC 8446 §4).
public struct TLSNegotiatedParameters: Sendable, Equatable {
    /// The negotiated cipher suite (§4.1.1).
    public let cipherSuite: TLSCipherSuite
    /// The key-exchange group the ECDHE leg ran over (§4.2.8).
    public let group: TLSNamedGroup
    /// The selected ALPN protocol (RFC 7301), when negotiated.
    public let alpnProtocol: String?
    /// The client's SNI host name (RFC 6066), when offered.
    public let serverName: String?
    /// Whether the handshake resumed via PSK (§4.2.11) rather than certificates.
    public let resumed: Bool
    /// Whether a HelloRetryRequest round happened (§4.1.4).
    public let usedHelloRetry: Bool
    /// The client's certificate chain, leaf first, DER (§4.4.2) — empty when the client sent
    /// none or was never asked.
    ///
    /// Signature-verified (§4.4.3); chain validation is Phase 3c's.
    public let clientCertificateChainDER: [[UInt8]]
    /// The peer's RFC 8449 `record_size_limit`, when it sent one (already honored outbound).
    public let peerRecordSizeLimit: Int?
}
