//
//  HTTP3Error.swift
//  HTTP3
//
//  RFC 9114 §8 — HTTP/3 errors come in two scopes, mirroring HTTP/2. A connection error is fatal: the
//  endpoint closes the connection (CONNECTION_CLOSE / a GOAWAY then close) with the error code. A
//  stream error affects one request stream: the endpoint resets it (RESET_STREAM + STOP_SENDING) and
//  the connection continues. The scope is the presence of a stream id.
//
//  The carried `code` is the raw QUIC application error code so it can express either an HTTP/3 code
//  (RFC 9114 §8.1) or a QPACK code (RFC 9204 §6) — a QPACK fault surfaces as a connection error
//  carrying the QPACK code. The named constructors build it from the typed registries.
//

public import HTTPCore
public import QPACK

/// An HTTP/3 error, scoped to the connection or to a single stream (RFC 9114 §8).
public struct HTTP3Error: Error, Sendable, Equatable {
    /// The QUIC application error code reported to the peer (RFC 9114 §8.1 / RFC 9204 §6).
    public let code: UInt64

    /// The affected stream, or `nil` for a connection error.
    public let streamID: QUICStreamID?

    /// A human-readable diagnostic (not sent on the wire).
    public let reason: String

    /// Creates an error from a raw QUIC application error code and an explicit scope.
    public init(code: UInt64, streamID: QUICStreamID? = nil, reason: String = "") {
        self.code = code
        self.streamID = streamID
        self.reason = reason
    }

    /// Whether this is a connection error (fatal — close the connection, RFC 9114 §8).
    public var isConnectionError: Bool { streamID == nil }

    /// A connection error carrying an HTTP/3 code (RFC 9114 §8.1).
    public static func connection(_ code: HTTP3ErrorCode, _ reason: String = "") -> Self {
        Self(code: code.rawValue, streamID: nil, reason: reason)
    }

    /// A stream error on `streamID` carrying an HTTP/3 code (RFC 9114 §8.1).
    public static func stream(
        _ streamID: QUICStreamID,
        _ code: HTTP3ErrorCode,
        _ reason: String = ""
    ) -> Self {
        Self(code: code.rawValue, streamID: streamID, reason: reason)
    }

    /// A connection error carrying a QPACK code (RFC 9204 §6) — a QPACK fault is always fatal.
    public static func connection(qpack code: QPACKError.Code, _ reason: String = "") -> Self {
        Self(code: UInt64(code.rawValue), streamID: nil, reason: reason)
    }
}
