//
//  WebSocketHandler.swift
//  WebSocket
//
//  The application seam the server drives once a connection has upgraded (RFC 6455 §4): given a
//  connection event, the handler returns the frames to send back. Returning actions (rather than
//  mutating the connection) keeps the handler free of the engine's exclusive-access requirements and
//  trivially testable.
//

public import HTTPCore

/// Application logic for an upgraded WebSocket connection (RFC 6455 §5 / §6).
public protocol WebSocketHandler: Sendable {
    /// Whether to upgrade `request` to WebSocket (e.g. gate by path); defaults to accepting any valid
    /// upgrade request (RFC 6455 §4).
    func shouldUpgrade(_ request: HTTPRequest) -> Bool

    /// Whether to accept an upgrade from this `Origin` (nil when the client sent no `Origin`).
    ///
    /// WebSocket handshakes are exempt from the Same-Origin Policy and CORS, so a malicious page can
    /// open one against your server with the victim's ambient credentials — cross-site WebSocket
    /// hijacking (RFC 6455 §10.2, CWE-346/CWE-1385). The default is **secure**: it admits only requests
    /// with no `Origin` (non-browser clients) and rejects every browser-supplied origin until you
    /// override this to allowlist the origins you trust.
    func isOriginAllowed(_ origin: String?) -> Bool

    /// Returns the frames to send in response to `event` (RFC 6455 §5 / §6).
    func handle(_ event: WebSocketConnection.Event) async -> [WebSocketAction]

    /// Called once when the connection is established — after the upgrade completes (h1 `101`, or the
    /// Extended-CONNECT accept on h2/h3, RFC 8441 / RFC 9220) and before any peer frame is delivered.
    ///
    /// Returns the frames to send first (a greeting, a protocol hello); the default sends none. This
    /// is the only place a handler can speak *first* — ``handle(_:)`` runs only when the peer sends.
    func onOpen() async -> [WebSocketAction]

    /// Called exactly once when the session ends — a clean Close handshake, an abrupt peer EOF, a
    /// protocol failure, or the server tearing the connection down.
    ///
    /// The last call the handler receives for the connection; use it to release per-connection state.
    /// (``handle(_:)``'s `.close` event fires only for a *peer-sent* Close frame — this fires for
    /// every ending, RFC 6455 §7.) The default does nothing.
    func onClose() async
}

extension WebSocketHandler {
    /// By default any request that already passed the handshake is upgraded.
    public func shouldUpgrade(_: HTTPRequest) -> Bool { true }

    /// By default only a request with no `Origin` is admitted — i.e. a non-browser client.
    ///
    /// Browsers always send `Origin` on a WebSocket handshake, so this rejects every browser (and thus
    /// every cross-site) upgrade until the app allowlists its trusted origins — secure-by-default
    /// against cross-site WebSocket hijacking (RFC 6455 §10.2, CWE-346/1385). Override to admit specific
    /// origins, e.g. `{ $0 == "https://app.example" }`.
    public func isOriginAllowed(_ origin: String?) -> Bool { origin == nil }

    /// By default a handler sends nothing on open (the pre-hooks behavior, unchanged).
    public func onOpen() async -> [WebSocketAction] { [] }

    /// By default a handler observes nothing on close (the pre-hooks behavior, unchanged).
    public func onClose() async {
        // Optional lifecycle hook — no per-connection state to release by default.
    }
}
