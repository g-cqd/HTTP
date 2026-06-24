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

/// A frame an application asks the connection to send in response to an event (RFC 6455 §5).
public enum WebSocketAction: Sendable, Equatable {
    /// Send a text message (RFC 6455 §5.6).
    case sendText(String)

    /// Send a binary message (RFC 6455 §5.6).
    case sendBinary([UInt8])

    /// Send a Ping (RFC 6455 §5.5.2).
    case sendPing([UInt8])

    /// Begin the closing handshake with a status code and reason (RFC 6455 §5.5.1).
    case close(WebSocketCloseCode, reason: String)
}

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

/// A ``WebSocketHandler`` backed by closures.
public struct ClosureWebSocketHandler: WebSocketHandler {
    private let upgrade: @Sendable (HTTPRequest) -> Bool
    private let originAllowed: @Sendable (String?) -> Bool
    private let onEvent: @Sendable (WebSocketConnection.Event) async -> [WebSocketAction]

    /// Creates a handler from an optional upgrade predicate, an optional `Origin` allowlist predicate
    /// (defaults to accepting any origin — override for credentialed endpoints, RFC 6455 §10.2), and
    /// an event handler.
    public init(
        shouldUpgrade: @escaping @Sendable (HTTPRequest) -> Bool = { _ in true },
        isOriginAllowed: @escaping @Sendable (String?) -> Bool = { _ in true },
        handle: @escaping @Sendable (WebSocketConnection.Event) async -> [WebSocketAction]
    ) {
        self.upgrade = shouldUpgrade
        self.originAllowed = isOriginAllowed
        self.onEvent = handle
    }

    /// Asks the upgrade predicate.
    public func shouldUpgrade(_ request: HTTPRequest) -> Bool { upgrade(request) }

    /// Asks the origin-allowlist predicate.
    public func isOriginAllowed(_ origin: String?) -> Bool { originAllowed(origin) }

    /// Invokes the event closure.
    public func handle(_ event: WebSocketConnection.Event) async -> [WebSocketAction] {
        await onEvent(event)
    }
}

extension WebSocketConnection {
    /// Applies an application `action`, queuing the corresponding frame (RFC 6455 §5).
    public mutating func apply(_ action: WebSocketAction) {
        switch action {
            case .sendText(let text): send(text: text)
            case .sendBinary(let bytes): send(binary: bytes)
            case .sendPing(let payload): sendPing(payload)
            case .close(let code, let reason): close(code, reason: reason)
        }
    }
}
