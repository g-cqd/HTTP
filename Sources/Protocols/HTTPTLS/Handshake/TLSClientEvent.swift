//
//  TLSClientEvent.swift
//  HTTPTLS
//
//  What ``TLSClientConnection/receive(_:)`` surfaces to its driver — the client mirror of
//  ``TLSServerEvent`` (RFC 8446 §4 / §5 / §6).
//

/// One connection-visible event from ``TLSClientConnection/receive(_:)``.
public enum TLSClientEvent: Sendable, Equatable {
    /// The handshake completed (server Certificate + CertificateVerify + Finished verified,
    /// client Finished queued, §4.4.4); application data may flow.
    case handshakeCompleted(TLSNegotiatedParameters)
    /// Decrypted application data (§5.2; empty records are dropped).
    case applicationData([UInt8])
    /// The peer sent `close_notify` (§6.1).
    case peerClosed
}
