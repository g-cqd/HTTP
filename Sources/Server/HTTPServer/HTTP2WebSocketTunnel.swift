//
//  HTTP2WebSocketTunnel.swift
//  HTTPServer
//
//  A live WebSocket-over-HTTP/2 tunnel (RFC 8441 / RFC 9220), from the merged-mailbox consumer's point of
//  view: the consumption-gated channel it feeds tunnel DATA into, and the signal that channel's reader
//  reports back through. The per-stream sans-I/O ``WebSocketConnection`` engine and the route's
//  ``WebSocketHandler`` live only inside that stream's dedicated pump task (`HTTPServer.runHTTP2Tunnel`),
//  never touched by the consumer — so a single HTTP/2 connection can multiplex tunnels to different
//  WebSocket routes AND a slow tunnel handler on one of them never blocks another stream (buffered
//  request, native-streaming response, or sibling tunnel) multiplexed on the same connection.
//
//  The channel replaces an `.unbounded` `AsyncStream` (2026-07-31 audit, finding 2). Tunnel DATA is
//  opaque (RFC 8441 §5): it is never buffered as a request body and never bounded by the body limit, so
//  before this it was bounded by *nothing* — a conforming peer talking to a blocked handler could grow
//  the server's memory without limit. Now the tunnel's receive window is debited on arrival and credited
//  only as its handler consumes, so a blocked handler stalls its peer at `streamReceiveWindow` instead.
//

/// The consumer's handle to one live WebSocket-over-HTTP/2 tunnel's dedicated pump task.
struct HTTP2WebSocketTunnel: Sendable {
    /// Carries tunnel DATA to this stream's pump task, in order, bounded by the receive window.
    ///
    /// Its terminal state is the peer-ended signal: `finish()` delivers every already-queued chunk and
    /// then ends, so a tunnel closed by the peer still processes the frames that were in flight.
    let channel: BoundedByteChannel

    /// Reports the pump's consumption back to the consumer, which credits the receive windows.
    let signal: HTTP2ConsumptionSignal

    /// Cancels this tunnel's pump task when the peer resets the stream (RFC 9113 §6.4).
    ///
    /// Abandoning the channel already unblocks a pump waiting on inbound; this additionally unblocks one
    /// parked inside the route's `handler.handle(event)`, which no amount of channel teardown reaches.
    let canceller: HTTP2StreamCanceller
}
