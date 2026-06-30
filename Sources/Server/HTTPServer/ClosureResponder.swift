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
    private let handler:
        @Sendable (HTTPRequest, RequestBody, RequestContext) async -> ServerResponse

    /// Creates a responder from a request-handling closure receiving the body and per-request context.
    public init(
        _ handler:
            @escaping @Sendable (HTTPRequest, RequestBody, RequestContext) async ->
            ServerResponse
    ) {
        self.handler = handler
    }

    /// Invokes the wrapped closure.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext
    ) async -> ServerResponse {
        await handler(request, body, context)
    }
}
