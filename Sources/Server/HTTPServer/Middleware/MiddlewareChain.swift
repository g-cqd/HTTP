//
//  MiddlewareChain.swift
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
