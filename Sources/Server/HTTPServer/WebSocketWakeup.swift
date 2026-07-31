//
//  WebSocketWakeup.swift
//  HTTPServer
//
//  One thing the HTTP/1.1 WebSocket pump wakes for. Feeding both sources through a single
//  ``AsyncStream`` lets the pump merge the connection's reader task and the broadcast hub as one
//  consumer — so the server can push a frame without the loop blocking on `receive`.
//
//  These are payload-free *tickets* (2026-07-31 audit, finding 1). The payloads live in the two
//  bounded structures beside the mailbox — ``BoundedByteChannel`` for lossless transport octets and
//  ``WebSocketBroadcastMailbox`` for droppable broadcasts — because those two halves need opposite
//  policies and cannot share a queue. Carrying only tickets is what lets this stream stay
//  `.unbounded` while being *provably* bounded: inbound tickets are 1:1 with queued chunks, which the
//  channel caps at `maxQueuedInboundChunks`, and the broadcast edge is coalesced to at most one
//  outstanding ticket. The previous `.bufferingNewest(256)` policy dropped the *oldest* wakeup on
//  overflow, and dropping an inbound octet chunk desynchronizes the resumable frame parser.
//

/// A wakeup for the HTTP/1.1 WebSocket pump — a ticket, not a payload.
enum WebSocketWakeup: Sendable {
    /// At least one item (a chunk, or the terminal state) is queued in the transport intake channel.
    ///
    /// Exactly one is yielded per item, so the pump's matching `next()` never suspends.
    case inboundReady
    /// The broadcast mailbox is non-empty; the edge is coalesced, so at most one is outstanding.
    case broadcastReady
}
