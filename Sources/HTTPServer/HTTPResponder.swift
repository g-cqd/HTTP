//
//  HTTPResponder.swift
//  HTTPServer
//
//  The request-handling interface the server drives. Deliberately a plain protocol (plus a closure
//  adapter) for now; the result-builder routing DSL will conform to it as a later layer.
//

public import HTTPCore

/// A response to send back: the status/header message (RFC 9110 §3) and its body bytes.
public struct ServerResponse: Sendable, Equatable {

    /// The response head (status + header fields).
    public var head: HTTPResponse

    /// The response body.
    public var body: [UInt8]

    /// Creates a response from a head and (optionally) a body.
    public init(_ head: HTTPResponse, body: [UInt8] = []) {
        self.head = head
        self.body = body
    }
}

/// Produces a ``ServerResponse`` for a parsed request.
///
/// The unit of application logic the server runs; the routing DSL will conform to it later.
public protocol HTTPResponder: Sendable {

    /// Responds to `request` (with its decoded `body`).
    func respond(to request: HTTPRequest, body: [UInt8]) async -> ServerResponse
}

/// An ``HTTPResponder`` backed by a closure.
public struct ClosureResponder: HTTPResponder {

    private let handler: @Sendable (HTTPRequest, [UInt8]) async -> ServerResponse

    /// Creates a responder from a request-handling closure.
    public init(_ handler: @escaping @Sendable (HTTPRequest, [UInt8]) async -> ServerResponse) {
        self.handler = handler
    }

    /// Invokes the wrapped closure.
    public func respond(to request: HTTPRequest, body: [UInt8]) async -> ServerResponse {
        await handler(request, body)
    }
}
