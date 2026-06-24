//
//  HTTP2ErrorCode.swift
//  HTTP2
//
//  RFC 9113 §7 — the 32-bit error codes carried by RST_STREAM and GOAWAY. Unknown codes are treated
//  as INTERNAL_ERROR (§7), so decoding never fails on an unrecognized value.
//

/// An HTTP/2 error code (RFC 9113 §7).
public enum HTTP2ErrorCode: UInt32, Sendable, Equatable, Hashable {
    /// Graceful shutdown (§7).
    case noError = 0x0
    /// A protocol error not covered by a more specific code (§7).
    case protocolError = 0x1
    /// An unexpected internal error (§7).
    case internalError = 0x2
    /// A flow-control protocol violation (§7).
    case flowControlError = 0x3
    /// A SETTINGS frame was not acknowledged in time (§7).
    case settingsTimeout = 0x4
    /// A frame arrived on a half-closed or closed stream (§7).
    case streamClosed = 0x5
    /// A frame's size was invalid for its type (§7).
    case frameSizeError = 0x6
    /// A stream was refused before application processing (§7).
    case refusedStream = 0x7
    /// A stream is no longer needed (§7).
    case cancel = 0x8
    /// The HPACK decoder state was corrupted (§7).
    case compressionError = 0x9
    /// A CONNECT request's tunnel connection failed (§7).
    case connectError = 0xa
    /// The peer is generating excessive load (§7) — the Rapid Reset / flood response.
    case enhanceYourCalm = 0xb
    /// The transport security does not meet HTTP/2's requirements (§7).
    case inadequateSecurity = 0xc
    /// The request must be retried over HTTP/1.1 (§7).
    case http11Required = 0xd

    /// Maps a wire value to a code, treating unknown values as INTERNAL_ERROR (RFC 9113 §7).
    public init(code: UInt32) {
        self = Self(rawValue: code) ?? .internalError
    }
}
