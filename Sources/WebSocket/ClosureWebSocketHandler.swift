//
//  ClosureWebSocketHandler.swift
//  WebSocket
//
//  The application seam the server drives once a connection has upgraded (RFC 6455 §4): given a
//  connection event, the handler returns the frames to send back. Returning actions (rather than
//  mutating the connection) keeps the handler free of the engine's exclusive-access requirements and
//  trivially testable.
//

public import HTTPCore

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
