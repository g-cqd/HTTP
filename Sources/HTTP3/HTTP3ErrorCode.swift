//
//  HTTP3ErrorCode.swift
//  HTTP3
//
//  RFC 9114 §8.1 — the HTTP/3 error codes, carried as a QUIC application error code (a variable-length
//  integer) on RESET_STREAM, STOP_SENDING, or CONNECTION_CLOSE. The 17 defined codes are locked to
//  their wire values; QPACK adds three more (RFC 9204 §6) in its own registry. Unknown codes received
//  from a peer are treated as H3_NO_ERROR for the purpose of reacting (RFC 9114 §8.1).
//

/// An HTTP/3 error code (RFC 9114 §8.1); the raw value is the QUIC application error code.
public enum HTTP3ErrorCode: UInt64, Sendable, Equatable, Hashable, CaseIterable {

    /// No error — graceful closure (§8.1).
    case h3NoError = 0x0100
    /// A protocol error not covered by a more specific code (§8.1).
    case h3GeneralProtocolError = 0x0101
    /// An internal error (§8.1).
    case h3InternalError = 0x0102
    /// A stream was created in an incorrect direction or at an invalid time (§8.1).
    case h3StreamCreationError = 0x0103
    /// A required critical stream (control or QPACK) was closed (§8.1).
    case h3ClosedCriticalStream = 0x0104
    /// A frame was received on a stream where it is not permitted, or out of sequence (§8.1).
    case h3FrameUnexpected = 0x0105
    /// A frame was malformed or the wrong size for its type (§8.1).
    case h3FrameError = 0x0106
    /// The peer is generating excessive load (§8.1) — the Rapid Reset analog response.
    case h3ExcessiveLoad = 0x0107
    /// An identifier (stream / push) was used incorrectly, e.g. a GOAWAY that increases (§8.1).
    case h3IdError = 0x0108
    /// A SETTINGS frame contained an invalid or reserved setting (§8.1).
    case h3SettingsError = 0x0109
    /// The first frame on the control stream was not SETTINGS (§8.1).
    case h3MissingSettings = 0x010A
    /// The server refused the request before any application processing (§8.1).
    case h3RequestRejected = 0x010B
    /// The request or its response was cancelled (§8.1).
    case h3RequestCancelled = 0x010C
    /// A stream closed before the message was complete (§8.1).
    case h3RequestIncomplete = 0x010D
    /// An HTTP message was malformed (bad pseudo-headers, content-length mismatch, …) (§8.1).
    case h3MessageError = 0x010E
    /// A CONNECT request's tunnel could not be established (§8.1).
    case h3ConnectError = 0x010F
    /// The request should be retried over HTTP/1.1 or HTTP/2 (§8.1).
    case h3VersionFallback = 0x0110
}
