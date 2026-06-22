//
//  ParsedRequest.swift
//  HTTP1
//
//  The result of fully parsing one HTTP/1.1 request: the version-independent message plus its
//  decoded body (the wire framing — Content-Length or chunked — has already been resolved).
//

public import HTTPCore

/// A fully parsed HTTP/1.1 request: a version-independent ``HTTPRequest`` and its decoded body.
public struct ParsedRequest: Sendable, Equatable {

    /// The request message (method, authority, path, header fields).
    public let request: HTTPRequest

    /// The decoded message body (empty when the request has no body).
    public let body: [UInt8]

    /// The request-line version (RFC 9112 §2.3) — drives the §9.3 keep-alive default.
    ///
    /// `HTTPRequest` is version-independent by design, so the wire version is carried here for the
    /// HTTP/1.x runtime (HTTP/1.1 persists by default; HTTP/1.0 closes unless it asked to keep alive).
    public let version: HTTPVersion

    /// Creates a parsed request from a message, its decoded body, and its wire version.
    public init(request: HTTPRequest, body: [UInt8], version: HTTPVersion = .http11) {
        self.request = request
        self.body = body
        self.version = version
    }
}
