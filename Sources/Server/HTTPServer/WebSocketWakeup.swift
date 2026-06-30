//
//  WebSocketWakeup.swift
//  HTTPServer
//
//  One thing the HTTP/1.1 WebSocket pump wakes for (Phase 2.7): inbound bytes off the wire, a hub
//  broadcast to deliver to this connection, or the read side closing. Feeding all three through a single
//  ``AsyncStream`` lets the pump merge the connection's reader task and the broadcast hub as one consumer
//  — so the server can push a frame without the loop blocking on `receive`.
//

internal import WebSocket

/// A wakeup for the HTTP/1.1 WebSocket pump: inbound bytes, a hub broadcast, or the reader closing.
enum WebSocketWakeup: Sendable {
    case inbound([UInt8])
    case broadcast(WebSocketMessage)
    case closed
}
