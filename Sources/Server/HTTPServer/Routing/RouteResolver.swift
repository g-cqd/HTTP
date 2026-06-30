//
//  RouteResolver.swift
//  HTTPServer
//
//  An optional capability a responder advertises so the server can resolve route metadata from a request
//  *head* — the body limit, the WebSocket handler, the streaming opt-in — without running the handler or
//  reading the body. ``Router`` conforms; ``MiddlewareChain`` and the `wrapped(by:)` chain forward to the
//  responder they wrap, so a middleware-wrapped router stays resolvable. A responder that does not
//  conform leaves the server on its defaults (global body limit, buffered body, no per-route WebSocket).
//

public import HTTPCore

/// A responder that can resolve ``ResolvedRoute`` metadata from a request head (no body, no handler run).
public protocol RouteResolver: Sendable {
    /// The metadata for the route matching `method` + `path`, or `nil` when none matches.
    func resolve(method: HTTPMethod, path: String) -> ResolvedRoute?

    /// The metadata for the WebSocket route matching `path`, or `nil` when none matches.
    ///
    /// Method-agnostic, because an HTTP/2 or HTTP/3 WebSocket upgrade arrives as an Extended CONNECT
    /// (RFC 8441 / RFC 9220) whose `:method` is `CONNECT`, while the route is declared as a `GET`.
    func resolveWebSocket(path: String) -> ResolvedRoute?

    /// Whether any route declares a WebSocket handler — drives the Extended CONNECT advertisement
    /// (RFC 8441 §3 / RFC 9220).
    var hasWebSocketRoutes: Bool { get }
}
