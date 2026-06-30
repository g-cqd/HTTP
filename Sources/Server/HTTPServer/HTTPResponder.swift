//
//  HTTPResponder.swift
//  HTTPServer
//
//  The request-handling interface the server drives. Deliberately a plain protocol (plus a closure
//  adapter) for now; the result-builder routing DSL will conform to it as a later layer.
//

public import HTTPCore

/// Produces a ``ServerResponse`` for a parsed request, given its body and per-request context.
///
/// The unit of application logic the server runs; the routing DSL conforms to it. The seam carries an
/// explicit ``RequestContext`` (connection metadata, route parameters, correlation id, a typed storage
/// bag) and a ``RequestBody`` (buffered or streamed) so a responder can reach everything about the
/// in-flight request, not just its head and bytes.
public protocol HTTPResponder: Sendable {
    /// Responds to `request` with its `body` and `context`.
    func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext
    ) async -> ServerResponse
}

extension HTTPResponder {
    /// Convenience: respond to `request` with a buffered `body` and a default (empty) context.
    ///
    /// A shorthand for tests and direct, context-free invocation; the engines always call the full
    /// ``respond(to:body:context:)`` requirement.
    public func respond(to request: HTTPRequest, body: [UInt8] = []) async -> ServerResponse {
        await respond(to: request, body: .collected(body), context: RequestContext())
    }

    /// Convenience: respond to `request` with a buffered `body` and an explicit `context`.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        context: RequestContext
    ) async -> ServerResponse {
        await respond(to: request, body: .collected(body), context: context)
    }
}
