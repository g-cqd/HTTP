//
//  TLSServerEvent.swift
//  HTTPTLS
//
//  What ``TLSServerConnection/receive(_:)`` surfaces to its driver — the TLS analog of
//  `HTTP2Connection`'s event stream. Error alerts never appear here: they THROW (and funnel),
//  so a driver cannot observe an error without the connection already being terminal.
//

/// One connection-visible event from ``TLSServerConnection/receive(_:)``.
public enum TLSServerEvent: Sendable, Equatable {
    /// The handshake completed (client Finished verified, §4.4.4); application data may flow.
    case handshakeCompleted(TLSNegotiatedParameters)
    /// Decrypted application data (§5.2; empty records are dropped, never surfaced).
    case applicationData([UInt8])
    /// The peer sent `close_notify` (§6.1) — its write direction is done; the connection is
    /// terminal here (this server does not continue half-closed).
    case peerClosed
}
