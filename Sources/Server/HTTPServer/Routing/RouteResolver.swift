//
//  RouteResolver.swift
//  HTTPServer
//
//  An optional capability a responder advertises so the server can match a route from a request *head* —
//  the body limit, the WebSocket handler, the streaming opt-in, the captured parameters — without running
//  the handler or reading the body. ``Router`` conforms; ``MiddlewareChain`` and the `wrapped(by:)` chain
//  forward to the responder they wrap, so a middleware-wrapped router stays resolvable. A responder that
//  does not conform leaves the server on its defaults (global body limit, buffered body, no per-route
//  WebSocket).
//
//  ONE entry point, not two. There used to be `resolve(method:path:)` and `resolveWebSocket(path:)`, each
//  re-splitting the path and re-scanning the table; the second existed only because a WebSocket upgrade
//  may arrive under a method the route was not declared with — an h1 `GET` with `Upgrade: websocket`
//  (RFC 6455 §4.1), or an Extended CONNECT whose `:method` is `CONNECT` against a `GET` route (RFC 8441
//  §4 / RFC 9220 §3). That is a *predicate on the match*, not a different query, so it is now a flag:
//  one path split, one scan, one answer (2026-07-31 audit, finding 19).
//

public import HTTPCore

/// A responder that can match a route from a request head (no body, no handler run).
public protocol RouteResolver: Sendable {
    /// The route matching `method` + `path`, or `nil` when none does.
    ///
    /// `isUpgrade` selects the WebSocket-handshake reading of the table: only routes carrying a
    /// WebSocket handler are considered, and the request method is ignored, because an upgrade arrives
    /// under a method the route was not declared with (RFC 6455 §4.1; RFC 8441 §4 / RFC 9220 §3).
    /// Otherwise the method must match, with `HEAD` folded onto `GET` (RFC 9110 §9.3.2).
    func match(method: HTTPMethod, path: String, isUpgrade: Bool) -> RouteMatch?

    /// Whether any route declares a WebSocket handler — drives the Extended CONNECT advertisement
    /// (RFC 8441 §3 / RFC 9220).
    var hasWebSocketRoutes: Bool { get }
}
