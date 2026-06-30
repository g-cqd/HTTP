//
//  Route+WebSocket.swift
//  HTTPServer
//
//  RFC 6455 §4 / RFC 8441 / RFC 9220 — declaring a WebSocket endpoint as a route. A `.webSocket` route
//  is matched as a `GET` (the HTTP/1.1 upgrade is a GET; the HTTP/2 + HTTP/3 Extended CONNECT is resolved
//  per path), so it shares the router table with ordinary routes. The server drives the live connection
//  outside `respond` once it decides to upgrade; a *non-upgrade* `GET` to a WebSocket path falls through
//  to the route's handler, which answers `426 Upgrade Required` (RFC 9110 §15.5.22).
//

public import HTTPCore
public import WebSocket

extension Route {
    /// A WebSocket route at `pattern` (RFC 6455), driven by `handler` once the connection upgrades.
    ///
    /// Declared as a `GET` so it shares the router table with ordinary routes; the server resolves it per
    /// path and, on a real upgrade (HTTP/1.1 `Upgrade: websocket`, or an HTTP/2 / HTTP/3 Extended CONNECT,
    /// RFC 8441 / RFC 9220), hands the connection to `handler`. A *non-upgrade* `GET` to this path gets
    /// `426 Upgrade Required` (RFC 9110 §15.5.22).
    public static func webSocket(_ pattern: String, handler: any WebSocketHandler) -> Self {
        Self(
            .get,
            Self.parse(pattern),
            handler: { _, _, _ in Self.upgradeRequired() },
            middleware: [],
            webSocketHandler: handler
        )
    }

    /// A WebSocket route at `pattern` built from closures — a convenience over ``webSocket(_:handler:)``
    /// that wraps a ``ClosureWebSocketHandler`` (RFC 6455).
    ///
    /// The defaults match `ClosureWebSocketHandler`: every upgrade is accepted, and the secure origin
    /// policy admits only a no-`Origin` (non-browser) client — override `isOriginAllowed` to allowlist
    /// trusted browser origins (RFC 6455 §10.2).
    public static func webSocket(
        _ pattern: String,
        shouldUpgrade: @escaping @Sendable (HTTPRequest) -> Bool = { _ in true },
        isOriginAllowed: @escaping @Sendable (String?) -> Bool = { $0 == nil },
        handle: @escaping @Sendable (WebSocketConnection.Event) async -> [WebSocketAction]
    ) -> Self {
        webSocket(
            pattern,
            handler: ClosureWebSocketHandler(
                shouldUpgrade: shouldUpgrade,
                isOriginAllowed: isOriginAllowed,
                handle: handle
            )
        )
    }

    /// The `426 Upgrade Required` a *non-upgrade* request to a WebSocket path receives (RFC 9110
    /// §15.5.22): a 426 must advertise the required protocol via `Upgrade`, so a conforming client retries
    /// the request as a WebSocket handshake (RFC 9110 §7.8).
    static func upgradeRequired() -> ServerResponse {
        var head = HTTPResponse(status: .upgradeRequired)
        _ = head.headerFields.setValue("websocket", for: .upgrade)
        _ = head.headerFields.setValue("Upgrade", for: .connection)
        return ServerResponse(head)
    }
}
