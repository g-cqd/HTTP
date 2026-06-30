//
//  ResolvedRoute.swift
//  HTTPServer
//
//  The route metadata the server resolves from a request *head* (method + path) before reading the body
//  or running the handler: the per-route body limit (RFC 9110 §15.5.14), the route's WebSocket handler
//  (RFC 6455), and whether the route streams its request body. Produced by a ``RouteResolver`` (the
//  ``Router``) and consumed by the engines at the head — so a body limit is enforced before buffering and
//  a WebSocket upgrade is dispatched per path.
//

public import WebSocket

/// Per-route metadata resolved from a request head, before the body is read or the handler runs.
public struct ResolvedRoute: Sendable {
    /// The maximum request-body size for this route in octets, or `nil` to use the global
    /// ``HTTPLimits/maxBodySize`` (RFC 9110 §15.5.14).
    public var bodyLimit: Int?

    /// The WebSocket handler bound to this route (RFC 6455), or `nil` for an ordinary HTTP route.
    public var webSocketHandler: (any WebSocketHandler)?

    /// Whether the route consumes its request body incrementally (``RequestBody/stream(_:)``) rather
    /// than buffered.
    public var streamsBody: Bool

    /// Creates resolved route metadata.
    public init(
        bodyLimit: Int? = nil,
        webSocketHandler: (any WebSocketHandler)? = nil,
        streamsBody: Bool = false
    ) {
        self.bodyLimit = bodyLimit
        self.webSocketHandler = webSocketHandler
        self.streamsBody = streamsBody
    }
}
