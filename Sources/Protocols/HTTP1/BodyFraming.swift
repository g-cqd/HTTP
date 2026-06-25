//
//  BodyFraming.swift
//  HTTP1
//
//  RFC 9112 §6 — how a request body is delimited on the wire (extracted from RequestParser.swift so
//  each file holds a single top-level declaration).
//

/// How a request body is delimited on the wire (RFC 9112 §6).
public enum BodyFraming: Sendable, Equatable {
    /// No body (no `Content-Length`, no `Transfer-Encoding`).
    case none

    /// A fixed-length body of `Content-Length` octets (RFC 9112 §6.2).
    case contentLength(Int)

    /// A `Transfer-Encoding: chunked` body (RFC 9112 §6.1 / §7.1).
    case chunked
}
