//
//  HTTP2Error.swift
//  HTTP2
//
//  RFC 9113 §5.4 — HTTP/2 errors come in two scopes. A connection error (§5.4.1) is fatal: the
//  endpoint sends GOAWAY with the error code and closes. A stream error (§5.4.2) affects one stream:
//  the endpoint sends RST_STREAM and the connection continues. The scope is the presence of a stream
//  id.
//

/// An HTTP/2 error, scoped to the connection or to a single stream (RFC 9113 §5.4).
public struct HTTP2Error: Error, Sendable, Equatable {
    /// The error code reported to the peer (RFC 9113 §7).
    public let code: HTTP2ErrorCode

    /// The affected stream, or `nil` for a connection error (RFC 9113 §5.4.1 vs §5.4.2).
    public let streamID: HTTP2StreamID?

    /// A human-readable diagnostic (not sent on the wire).
    public let reason: String

    /// Creates an error with an explicit scope.
    public init(code: HTTP2ErrorCode, streamID: HTTP2StreamID? = nil, reason: String = "") {
        self.code = code
        self.streamID = streamID
        self.reason = reason
    }

    /// Whether this is a connection error (fatal — GOAWAY then close, RFC 9113 §5.4.1).
    public var isConnectionError: Bool { streamID == nil }

    /// A connection error: GOAWAY with `code`, then close (RFC 9113 §5.4.1).
    public static func connection(_ code: HTTP2ErrorCode, _ reason: String = "") -> Self {
        Self(code: code, streamID: nil, reason: reason)
    }

    /// A stream error on `streamID`: RST_STREAM with `code` (RFC 9113 §5.4.2).
    public static func stream(
        _ streamID: HTTP2StreamID,
        _ code: HTTP2ErrorCode,
        _ reason: String = ""
    ) -> Self {
        Self(code: code, streamID: streamID, reason: reason)
    }
}
