//
//  WebSocketAction.swift
//  WebSocket
//
//  The application seam the server drives once a connection has upgraded (RFC 6455 §4): given a
//  connection event, the handler returns the frames to send back. Returning actions (rather than
//  mutating the connection) keeps the handler free of the engine's exclusive-access requirements and
//  trivially testable.
//

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
