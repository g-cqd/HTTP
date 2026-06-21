//
//  HTTP1ParseError.swift
//  HTTP1
//
//  Typed errors for the RFC 9112 HTTP/1.1 parser. Every error fails the message closed.
//

/// A failure encountered while parsing an HTTP/1.1 message (RFC 9112).
///
/// The parser uses typed `throws(HTTP1ParseError)` so callers handle every case exhaustively and
/// can map each to the correct protocol response (e.g. `400`, `414`, `431`, `505`).
public enum HTTP1ParseError: Error, Sendable, Equatable {

    /// The request-line did not match `method SP request-target SP HTTP-version CRLF` (RFC 9112 §3).
    case malformedRequestLine

    /// The method was not a valid `token` (RFC 9110 §9.1).
    case invalidMethod

    /// The request-target was empty or otherwise invalid (RFC 9112 §3.2).
    case invalidTarget

    /// The HTTP-version token was not understood (RFC 9112 §2.3; → `505`).
    case unsupportedVersion

    /// The input ended before the header section's terminating blank line (more data is needed).
    case incompleteHeaders

    /// A line was not terminated by CRLF — a bare CR or LF is a framing error (RFC 9112 §2.2).
    case malformedHeaders

    /// A header line began with whitespace: obsolete line folding, rejected (RFC 9112 §5.2).
    case obsoleteLineFolding

    /// A header line contained no `:` separator (RFC 9112 §5).
    case missingColon

    /// A field-name was empty or not a valid `token`, including whitespace before the `:`
    /// (RFC 9110 §5.1, RFC 9112 §5.1).
    case invalidFieldName

    /// A field-value contained an illegal octet (RFC 9110 §5.5).
    case invalidFieldValue

    /// A single field exceeded ``HTTPLimits/maxFieldSize`` (→ `431`).
    case fieldTooLarge

    /// The header section exceeded ``HTTPLimits/maxHeaderListSize`` (→ `431`).
    case headerSectionTooLarge

    /// The message carried more than ``HTTPLimits/maxFieldCount`` fields (→ `431`).
    case tooManyFields

    /// A chunk-size was empty, contained a non-hex digit, or overflowed `Int` (RFC 9112 §7.1).
    case invalidChunkSize

    /// A chunk was framed incorrectly — missing the CRLF around its data (RFC 9112 §7.1).
    case malformedChunk

    /// The decoded body exceeded ``HTTPLimits/maxBodySize`` (→ `413`).
    case bodyTooLarge

    /// The input ended before the body was fully framed (more data is needed).
    case incompleteBody
}
