//
//  HTTP2WebSocketTunnel.swift
//  HTTPServer
//
//  A live WebSocket-over-HTTP/2 tunnel (RFC 8441 / RFC 9220): the per-stream sans-I/O
//  ``WebSocketConnection`` engine paired with the route's ``WebSocketHandler``. The handler is stored per
//  stream because it is resolved once, from the request path, at the Extended CONNECT — and a tunnel DATA
//  frame carries only its stream id, not the path, so the route cannot be re-resolved per chunk. A single
//  HTTP/2 connection can multiplex tunnels to different WebSocket routes, so each stream keeps its own.
//

internal import WebSocket

/// A live WebSocket-over-HTTP/2 tunnel: its engine plus the handler resolved at the Extended CONNECT.
struct HTTP2WebSocketTunnel {
    /// The per-stream WebSocket protocol engine (RFC 6455).
    var socket: WebSocketConnection
    /// The route's handler, resolved once at the Extended CONNECT (tunnel DATA carries no path).
    let handler: any WebSocketHandler
}
