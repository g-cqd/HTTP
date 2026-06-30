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
public struct MiddlewareChain: HTTPResponder, RouteResolver {
    private let composed: any HTTPResponder

    /// Composes `middleware` (first outermost) around the `responder` that terminates the chain.
    public init(_ middleware: [any HTTPMiddleware], terminatingAt responder: any HTTPResponder) {
        self.composed = responder.wrapped(by: middleware)
    }

    /// Runs the request through the chain.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext
    ) async -> ServerResponse {
        await composed.respond(to: request, body: body, context: context)
    }

    /// Resolves a route's metadata at the head by forwarding to the wrapped responder — a middleware
    /// chain around a ``Router`` stays resolvable, since middleware never changes which route matches.
    public func resolve(method: HTTPMethod, path: String) -> ResolvedRoute? {
        (composed as? (any RouteResolver))?.resolve(method: method, path: path)
    }

    /// Resolves a WebSocket route for `path` by forwarding to the wrapped responder.
    public func resolveWebSocket(path: String) -> ResolvedRoute? {
        (composed as? (any RouteResolver))?.resolveWebSocket(path: path)
    }

    /// Whether the wrapped responder declares any WebSocket route (RFC 8441 / RFC 9220 advertisement).
    public var hasWebSocketRoutes: Bool {
        (composed as? (any RouteResolver))?.hasWebSocketRoutes ?? false
    }
}
