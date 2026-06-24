//
//  HTTPMiddleware.swift
//  HTTPServer
//
//  The middleware abstraction (RFC 9110 — cross-cutting request/response processing). A middleware is
//  a transformer interposed in front of a final ``HTTPResponder``: it inspects or rewrites the
//  request, delegates to `next` (or short-circuits by not calling it), and inspects or rewrites the
//  response. Because both a middleware-wrapped responder and the application are just ``HTTPResponder``
//  values, a consumer can implement their own middleware, compose an ordered chain, and reorder or
//  replace entries — without the server knowing anything about it.
//

public import HTTPCore

/// A request/response transformer interposed in front of an ``HTTPResponder`` (the middleware
/// pattern).
///
/// Conform to add cross-cutting behaviour — logging, CORS, compression, auth, headers — then compose
/// it with ``HTTPResponder/wrapped(by:)`` or ``MiddlewareChain``.
public protocol HTTPMiddleware: Sendable {
    /// Processes `request` (with its decoded `body`), delegating to `next` to produce the response.
    ///
    /// Call `next.respond(to:body:)` to continue the chain — passing a rewritten request/body if
    /// desired — then return the response, possibly rewritten. Or return a response *without* calling
    /// `next` to short-circuit (e.g. a CORS preflight or an auth rejection).
    func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse
}
