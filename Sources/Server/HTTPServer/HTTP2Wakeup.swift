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
    /// One item — a chunk of inbound octets, or the terminal end-of-input — is queued in the reader's
    /// intake channel.
    ///
    /// A payload-free *ticket* (2026-07-31 audit, finding 3). The octets themselves live in a
    /// ``BoundedByteChannel`` that parks the reader at a byte watermark, which is what lets this stream
    /// stay `.unbounded` while being *provably* bounded: a ticket is 1:1 with a queued item, and the
    /// channel caps those at `maxQueuedInboundChunks`. Carrying the payload here instead let an
    /// adversarial peer outpace the consumer and grow memory without limit.
    ///
    /// End-of-input arrives *in band* through the same channel rather than as its own case, so it can
    /// never overtake octets that were read before it. It is not immediately connection-fatal: a request
    /// already fully received, an active native-streaming relay, or an open tunnel needs no further
    /// input to finish, only the chance to run. The consumer drains that in-flight work — abandoning
    /// exactly what does still need input, such as a streaming-route body mid-upload — and closes once
    /// none remains.
    case inboundReady

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
