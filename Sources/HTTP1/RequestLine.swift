//
//  RequestLine.swift
//  HTTP1
//
//  RFC 9112 §3 — the parsed request-line of an HTTP/1.1 request.
//

public import HTTPCore

/// A parsed HTTP/1.1 request-line: `method SP request-target SP HTTP-version` (RFC 9112 §3).
public struct RequestLine: Sendable, Equatable {

    /// The request method (RFC 9110 §9).
    public let method: HTTPMethod

    /// The request-target in its on-the-wire form (usually origin-form, e.g. `"/path?q=1"`).
    public let target: String

    /// The protocol version (RFC 9112 §2.3).
    public let version: HTTPVersion

    /// Creates a request-line from its parsed components.
    public init(method: HTTPMethod, target: String, version: HTTPVersion) {
        self.method = method
        self.target = target
        self.version = version
    }
}
