//
//  ClosureResponder.swift
//  HTTPServer
//
//  The request-handling interface the server drives. Deliberately a plain protocol (plus a closure
//  adapter) for now; the result-builder routing DSL will conform to it as a later layer.
//

public import HTTPCore

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
