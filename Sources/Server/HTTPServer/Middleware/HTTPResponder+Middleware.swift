//
//  HTTPResponder+Middleware.swift
//  HTTPServer
//
//  The middleware abstraction (RFC 9110 — cross-cutting request/response processing). A middleware is
//  a transformer interposed in front of a final ``HTTPResponder``: it inspects or rewrites the
//  request, delegates to `next` (or short-circuits by not calling it), and inspects or rewrites the
//  response. Because both a middleware-wrapped responder and the application are just ``HTTPResponder``
//  values, a consumer can implement their own middleware, compose an ordered chain, and reorder or
//  replace entries — without the server knowing anything about it.
//

internal import HTTPCore

/// One link of a middleware chain: a middleware bound to the responder that follows it.
private struct InterceptedResponder: HTTPResponder, RouteResolver {
    let middleware: any HTTPMiddleware
    let next: any HTTPResponder

    func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext
    ) async -> ServerResponse {
        await middleware.respond(to: request, body: body, context: context, next: next)
    }

    // Forward route resolution down the chain to the terminal responder (the ``Router``).
    func resolve(method: HTTPMethod, path: String) -> ResolvedRoute? {
        (next as? (any RouteResolver))?.resolve(method: method, path: path)
    }

    func resolveWebSocket(path: String) -> ResolvedRoute? {
        (next as? (any RouteResolver))?.resolveWebSocket(path: path)
    }

    var hasWebSocketRoutes: Bool {
        (next as? (any RouteResolver))?.hasWebSocketRoutes ?? false
    }
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
