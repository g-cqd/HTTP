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

extension HTTPResponder {

    /// This responder with `middleware` interposed in front of it (the middleware runs first).
    public func wrapped(by middleware: any HTTPMiddleware) -> any HTTPResponder {
        InterceptedResponder(middleware: middleware, next: self)
    }

    /// This responder wrapped by an ordered `middleware` chain — the first element is outermost (runs
    /// first on the request, last on the response).
    public func wrapped(by middleware: [any HTTPMiddleware]) -> any HTTPResponder {
        middleware.reversed().reduce(self) { responder, layer in responder.wrapped(by: layer) }
    }
}

/// An ``HTTPResponder`` that runs an ordered middleware chain around a final responder.
///
/// `MiddlewareChain([a, b, c], terminatingAt: app)` runs `a` outermost and `app` innermost. Reorder
/// or replace by editing the array; conform new behaviour by adopting ``HTTPMiddleware``.
public struct MiddlewareChain: HTTPResponder {

    private let composed: any HTTPResponder

    /// Composes `middleware` (first outermost) around the `responder` that terminates the chain.
    public init(_ middleware: [any HTTPMiddleware], terminatingAt responder: any HTTPResponder) {
        self.composed = responder.wrapped(by: middleware)
    }

    /// Runs the request through the chain.
    public func respond(to request: HTTPRequest, body: [UInt8]) async -> ServerResponse {
        await composed.respond(to: request, body: body)
    }
}

/// One link of a middleware chain: a middleware bound to the responder that follows it.
private struct InterceptedResponder: HTTPResponder {

    let middleware: any HTTPMiddleware
    let next: any HTTPResponder

    func respond(to request: HTTPRequest, body: [UInt8]) async -> ServerResponse {
        await middleware.respond(to: request, body: body, next: next)
    }
}
