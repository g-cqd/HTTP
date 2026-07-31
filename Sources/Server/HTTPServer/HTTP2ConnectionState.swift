//
//  HTTP2ConnectionState.swift
//  HTTPServer
//
//  Everything one HTTP/2 connection's merged-mailbox consumer owns, in one place.
//
//  The consumer is the SOLE reader/mutator of the engine and the SOLE caller of `connection.send`
//  (HPACK, flow-control, and frame-order correctness all depend on that). This type does not weaken
//  that invariant — it is a plain non-`Sendable` struct threaded `inout` through the consumer's own
//  helpers, never shared, never locked. It exists because those helpers previously took eight separate
//  `inout` parameters, which is what pushed `serveHTTP2` to cyclomatic complexity 29 against a
//  configured maximum of 12.
//

internal import HTTP2

/// The per-connection state owned by the HTTP/2 merged-mailbox consumer.
struct HTTP2ConnectionState {
    /// The sans-I/O protocol engine.
    ///
    /// Single-owner: only the consumer touches it.
    var engine: HTTP2Connection

    /// Per-stream WebSocket tunnels (RFC 8441) — each tunnel's mailbox; its own WebSocket engine and
    /// handler live inside that tunnel's pump task.
    var webSockets: [HTTP2StreamID: HTTP2WebSocketTunnel] = [:]

    /// In-flight streaming-route requests (Phase 1.4), each feeding a body stream its handler consumes.
    var streaming: [HTTP2StreamID: HTTP2StreamingRequest] = [:]

    /// Active native-streaming responses (P6b): each relay's pull-permission gate, keyed by stream.
    var relays: [HTTP2StreamID: HTTP2StreamPermit] = [:]

    /// Consumption reports from every *gated* stream — streaming-route requests and tunnels alike.
    ///
    /// Kept beside (not inside) `streaming` / `webSockets` so a `.consumed` wakeup can still be applied
    /// after the body has ended but before the handler has drained what was already queued: the peer
    /// gets its connection-window credit back at the moment the handler actually takes those octets,
    /// not at the arbitrary moment the body happened to end (RFC 9113 §6.9, ADR 0006).
    var consumption: [HTTP2StreamID: HTTP2ConsumptionSignal] = [:]

    /// Dispatched-but-not-yet-reported handler tasks (buffered and streaming-route alike).
    ///
    /// A request already fully received needs no more inbound data to finish, only the chance to run, so
    /// EOF drains these rather than cancelling them out from under itself.
    var pendingRequests = 0

    /// Dispatched-but-not-yet-`.tunnelEnded` tunnel pump tasks — the tunnel half of `pendingRequests`.
    var pendingTunnels = 0

    /// Whether graceful shutdown has already queued its GOAWAY (RFC 9113 §6.8 — queue it once).
    var sentGoAway = false

    /// Set once the reader reports end-of-input; no further octets will ever arrive.
    var readerClosed = false

    /// Whether every EOF-time obligation has cleared.
    ///
    /// Checked only once the reader has actually closed: while it has not, more octets keep arriving and
    /// the connection has no reason to close regardless of this being transiently true.
    var isDrained: Bool {
        readerClosed && pendingRequests == 0 && pendingTunnels == 0 && relays.isEmpty
    }

    /// Retires every per-stream obligation for `streamID` — the one place credit is handed back.
    ///
    /// Consumption gating gives the connection a hard memory bound only if a stream that goes away
    /// mid-body returns what it was holding; forgetting that on any single exit path silently shrinks
    /// the shared connection window for the rest of the connection's life (RFC 9113 §6.9.1). Every path
    /// that drops a gated stream — `requestReady`, `.streamReset`, `.tunnelEnded`, the EOF drain —
    /// funnels through here rather than each remembering, which is the same class of omission as the
    /// reset bug this series also fixes.
    ///
    /// Consumption the handler reported but the loop never drained needs no separate accounting:
    /// `releaseReceiveWindow` returns *all* of this stream's outstanding credit at once.
    mutating func retire(_ streamID: HTTP2StreamID) {
        consumption.removeValue(forKey: streamID)
        engine.releaseReceiveWindow(of: streamID)
    }

    /// Ends every in-flight request-body stream, so no handler stays parked on one that will never
    /// receive another chunk.
    ///
    /// Abandons rather than finishes: these are streams still mid-upload when the input ended, so the
    /// handler must observe truncation, not a clean end of body.
    mutating func finishAllStreaming() async {
        for (streamID, pending) in streaming {
            await pending.channel.abandon()
            retire(streamID)
        }
        streaming.removeAll()
    }

    /// Tells every open tunnel its peer has ended, so each pump runs its `onClose` exactly once.
    mutating func endAllTunnels() {
        for tunnel in webSockets.values {
            tunnel.mailbox.yield(.peerEnded)
            tunnel.mailbox.finish()
        }
        webSockets.removeAll()
    }
}
