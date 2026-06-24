//
//  RequestHead.swift
//  HTTP1
//
//  RFC 9112 — a parsed request head (request-line + headers, no body), extracted from
//  RequestParser.swift so each file holds a single top-level declaration.
//

public import HTTPCore

/// A parsed request head: the message, its wire version, and how its body is framed.
///
/// It deliberately excludes the body, so a server can frame the body incrementally as it arrives
/// without re-parsing the request-line and header section on every chunk.
public struct RequestHead: Sendable, Equatable {
    /// The request message (method, authority, path, header fields).
    public let request: HTTPRequest

    /// The request-line version (RFC 9112 §2.3).
    public let version: HTTPVersion

    /// How the body is delimited (RFC 9112 §6).
    public let framing: BodyFraming

    /// Creates a request head.
    public init(request: HTTPRequest, version: HTTPVersion, framing: BodyFraming) {
        self.request = request
        self.version = version
        self.framing = framing
    }
}
