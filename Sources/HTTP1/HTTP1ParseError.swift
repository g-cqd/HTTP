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
}
