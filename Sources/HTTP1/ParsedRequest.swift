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

    /// Creates a parsed request from a message and its decoded body.
    public init(request: HTTPRequest, body: [UInt8]) {
        self.request = request
        self.body = body
    }
}
