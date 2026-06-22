//
//  QPACKError.swift
//  QPACK
//
//  RFC 9204 §6 — the three QPACK error codes, carried as a QUIC application error when a stream or the
//  connection is closed. A field-section decoding fault is `QPACK_DECOMPRESSION_FAILED`; a malformed
//  encoder-stream instruction is `QPACK_ENCODER_STREAM_ERROR`; a malformed decoder-stream instruction
//  is `QPACK_DECODER_STREAM_ERROR`. The wire values are locked (0x0200/0x0201/0x0202) and must not
//  drift. The diagnostic `reason` is for logging only and is never sent on the wire.
//

/// A QPACK error with its RFC 9204 §6 wire code and a human-readable diagnostic.
public struct QPACKError: Error, Sendable, Equatable {

    /// A QPACK error code (RFC 9204 §6); the raw value is the wire code.
    public enum Code: UInt32, Sendable, Equatable {
        /// `QPACK_DECOMPRESSION_FAILED` (0x0200) — a field section could not be decoded.
        case decompressionFailed = 0x0200
        /// `QPACK_ENCODER_STREAM_ERROR` (0x0201) — a malformed encoder-stream instruction.
        case encoderStreamError = 0x0201
        /// `QPACK_DECODER_STREAM_ERROR` (0x0202) — a malformed decoder-stream instruction.
        case decoderStreamError = 0x0202
    }

    /// The error code reported to the peer (RFC 9204 §6).
    public let code: Code

    /// A human-readable diagnostic (not sent on the wire).
    public let reason: String

    /// Creates a QPACK error with an explicit code.
    public init(code: Code, reason: String = "") {
        self.code = code
        self.reason = reason
    }

    /// A field-section decoding failure: `QPACK_DECOMPRESSION_FAILED` (RFC 9204 §6).
    public static func decompressionFailed(_ reason: String = "") -> QPACKError {
        QPACKError(code: .decompressionFailed, reason: reason)
    }

    /// A malformed encoder-stream instruction: `QPACK_ENCODER_STREAM_ERROR` (RFC 9204 §6).
    public static func encoderStreamError(_ reason: String = "") -> QPACKError {
        QPACKError(code: .encoderStreamError, reason: reason)
    }

    /// A malformed decoder-stream instruction: `QPACK_DECODER_STREAM_ERROR` (RFC 9204 §6).
    public static func decoderStreamError(_ reason: String = "") -> QPACKError {
        QPACKError(code: .decoderStreamError, reason: reason)
    }
}
