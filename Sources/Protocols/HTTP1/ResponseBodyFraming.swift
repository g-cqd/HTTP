//
//  ResponseBodyFraming.swift
//  HTTP1
//
//  RFC 9112 §6.3 — how an HTTP/1.1 response body is delimited on the wire. Unlike requests, an
//  HTTP/1.x response with neither `Transfer-Encoding` nor `Content-Length` is delimited by peer
//  connection close (§6.3 rule 8).
//

/// How an HTTP/1.1 response body is delimited on the wire (RFC 9112 §6.3).
public enum ResponseBodyFraming: Sendable, Equatable {
    /// No body on the wire (`HEAD`, `1xx`, `204`, `304` — RFC 9112 §6.3 rules 1–2).
    case none

    /// A fixed-length body of `Content-Length` octets (RFC 9112 §6.3 rule 6).
    case contentLength(Int)

    /// A `Transfer-Encoding: chunked` body (RFC 9112 §6.3 rule 4 / §7.1).
    case chunked

    /// A close-delimited body read until transport EOF (RFC 9112 §6.3 rule 8).
    case untilEOF
}
