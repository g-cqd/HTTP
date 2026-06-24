//
//  WebSocketHandshakeError.swift
//  WebSocket
//
//  RFC 6455 §4.2.1 — the reasons a client's opening handshake is not a valid WebSocket upgrade, each
//  mapped to the HTTP status the server should reject it with (§4.4): 426 for a version mismatch (so
//  the client learns version 13 is required), 400 for everything else.
//

public import HTTPCore

/// Why a WebSocket opening handshake was rejected (RFC 6455 §4.2.1).
public enum WebSocketHandshakeError: Error, Sendable, Equatable {
    /// The request method was not GET (RFC 6455 §4.2.1).
    case methodNotGet

    /// The `Upgrade` header did not offer the `websocket` token (RFC 6455 §4.2.1).
    case missingUpgrade

    /// The `Connection` header did not include the `Upgrade` token (RFC 6455 §4.2.1).
    case missingConnectionUpgrade

    /// `Sec-WebSocket-Key` was absent or not a base64-encoded 16-octet value (RFC 6455 §4.1).
    case missingOrInvalidKey

    /// `Sec-WebSocket-Version` was not `13` (RFC 6455 §4.1).
    case unsupportedVersion

    /// The status to reject the handshake with (RFC 6455 §4.4): 426 for a version mismatch, else 400.
    public var rejectionStatus: HTTPStatus {
        switch self {
            case .unsupportedVersion:
                .upgradeRequired
            default:
                .badRequest
        }
    }
}
