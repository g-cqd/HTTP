//
//  HTTP2WebSocketTunnel.swift
//  HTTPServer
//
//  A live WebSocket-over-HTTP/2 tunnel (RFC 8441 / RFC 9220), from the merged-mailbox consumer's point of
//  view: just the mailbox it feeds tunnel DATA and the peer-ended signal into. The per-stream sans-I/O
//  ``WebSocketConnection`` engine and the route's ``WebSocketHandler`` live only inside that stream's
//  dedicated pump task (`HTTPServer.runHTTP2Tunnel`) now, never touched by the consumer — so a single
//  HTTP/2 connection can multiplex tunnels to different WebSocket routes AND a slow tunnel handler on one
//  of them never blocks another stream (buffered request, native-streaming response, or sibling tunnel)
//  multiplexed on the same connection.
//

/// The consumer's handle to one live WebSocket-over-HTTP/2 tunnel's dedicated pump task.
struct HTTP2WebSocketTunnel: Sendable {
    /// Feeds tunnel DATA and the peer-ended signal to this stream's pump task, in order.
    let mailbox: AsyncStream<HTTP2TunnelSignal>.Continuation
}
