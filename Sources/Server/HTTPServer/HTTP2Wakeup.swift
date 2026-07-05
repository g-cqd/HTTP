//
//  HTTP2Wakeup.swift
//  HTTPServer
//
//  One thing the HTTP/2 merged-mailbox consumer wakes for (the cross-batch dispatch fix): inbound octets
//  off the wire, a dispatched request's finished response, a native-streaming relay's next body item, a
//  tunnel pump's outbound bytes or self-initiated close, a local watchdog's lapse, or the reader closing.
//  Feeding all of these through a single ``AsyncStream`` lets a reader task own `connection.receive` in
//  its own continuous loop — decoupled from every handler/relay/tunnel task — while ONE sequential
//  consumer stays the sole owner of the engine and `connection.send` (HPACK / flow-control / frame-order
//  correctness). Mirrors ``WebSocketWakeup``, HTTP/2's multi-stream, multi-event-kind counterpart.
//

internal import HTTP2

/// A wakeup for the HTTP/2 merged-mailbox consumer (see ``HTTPServer/serveHTTP2(_:deadline:initialBytes:)``).
enum HTTP2Wakeup: Sendable {
    /// Inbound octets off the wire (or the reader's initial carryover) to feed `engine.receive`.
    case inbound([UInt8])

    /// The reader hit EOF, an idle-timeout lapse, or a read failure — no more `.inbound` will ever
    /// follow. NOT immediately connection-fatal: a request already fully received (dispatched to its own
    /// task before this arrived), an active native-streaming relay, or an open tunnel may still have
    /// meaningful work in flight — none of it needs any more input from the connection to finish, only
    /// the chance to actually run. The consumer drains that in-flight work (abandoning anything that DOES
    /// still need more input, e.g. a streaming-route request body mid-upload) and closes once none of it
    /// remains, rather than cancelling it out from under itself the instant this wakeup is seen.
    case closed

    /// A dispatched request's (buffered or streaming-route) handler finished; apply its response.
    case requestReady(HTTP2StreamID, ServerResponse)

    /// A native-streaming relay pulled its next body item — a chunk, or the terminal finished/failed
    /// state (P6b / RFC 9113 §8.1).
    case streamChunk(HTTP2StreamID, AsyncHandoff.Item)

    /// A tunnel pump produced bytes to relay as tunnel DATA (RFC 8441 §5).
    case tunnelOutbound(HTTP2StreamID, [UInt8])

    /// A tunnel pump's task has finished — for every ending: its own WebSocket engine decided to close,
    /// the peer ended the tunnel, or the connection is tearing down. `selfClosed` distinguishes the first
    /// case (the consumer must still tell the HTTP/2 engine to end the stream, `engine.closeTunnel`) from
    /// the other two (the engine/consumer already knows, via `.tunnelClosed` / `.streamReset` or the
    /// reader closing). The consumer tracks this so it can tell whether a tunnel is still doing
    /// meaningful work before closing the connection on EOF (see `.closed` below).
    case tunnelEnded(HTTP2StreamID, selfClosed: Bool)

    /// A local watchdog lapsed: the consumer's own send-deadline, or a relay's producer-pull deadline
    /// (see HTTPServer+HTTP2.swift's file comment on the local-``IdleDeadline`` design) — connection-
    /// fatal, matching the FIX #1 reap.
    case localDeadlineLapsed
}
