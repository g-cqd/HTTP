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
    /// hijacking (RFC 6455 §10.2, CWE-346/CWE-1385). The default accepts every origin, which is
    /// **unsafe for credentialed endpoints**: override this to allowlist trusted origins (and decide
    /// whether to admit credential-less non-browser clients that send no `Origin`).
    func isOriginAllowed(_ origin: String?) -> Bool

    /// Returns the frames to send in response to `event` (RFC 6455 §5 / §6).
    func handle(_ event: WebSocketConnection.Event) async -> [WebSocketAction]
}

extension WebSocketHandler {
    /// By default any request that already passed the handshake is upgraded.
    public func shouldUpgrade(_: HTTPRequest) -> Bool { true }

    /// By default every origin is accepted.
    ///
    /// Override to defend credentialed endpoints against cross-site WebSocket hijacking
    /// (RFC 6455 §10.2).
    public func isOriginAllowed(_: String?) -> Bool { true }
}
