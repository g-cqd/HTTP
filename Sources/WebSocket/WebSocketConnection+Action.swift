//
//  WebSocketConnection+Action.swift
//  WebSocket
//
//  The application seam the server drives once a connection has upgraded (RFC 6455 §4): given a
//  connection event, the handler returns the frames to send back. Returning actions (rather than
//  mutating the connection) keeps the handler free of the engine's exclusive-access requirements and
//  trivially testable.
//

extension WebSocketConnection {
    /// Applies an application `action`, queuing the corresponding frame (RFC 6455 §5).
    public mutating func apply(_ action: WebSocketAction) {
        switch action {
            case .sendText(let text):
                send(text: text)
            case .sendBinary(let bytes):
                send(binary: bytes)
            case .sendPing(let payload):
                sendPing(payload)
            case .close(let code, let reason):
                close(code, reason: reason)
        }
    }
}
