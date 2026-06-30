//
//  WebSocketMessage.swift
//  WebSocket
//
//  A complete WebSocket data message (RFC 6455 §5.6) as a value — text or binary — the unit a broadcast
//  hub fans out to many connections. Distinct from ``WebSocketAction`` (a reply the handler returns for
//  its own connection): a ``WebSocketMessage`` is content that may be delivered to any subscriber.
//

/// A WebSocket data message (RFC 6455 §5.6): UTF-8 `text` or `binary` bytes.
public enum WebSocketMessage: Sendable, Equatable {
    case text(String)
    case binary([UInt8])
}
