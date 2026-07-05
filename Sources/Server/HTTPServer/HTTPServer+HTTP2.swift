//
//  HTTPServer+HTTP2.swift
//  HTTPServer
//
//  The server's HTTP/2 (RFC 9113) serve loop: drive the sans-I/O HTTP2Connection over a transport
//  connection — feed octets → events → respond → flush — until EOF, a timeout, a connection-level
//  protocol error, or a graceful shutdown drains the in-flight streams (RFC 9113 §6.8). Split out of
//  HTTPServer.swift so the runtime file stays focused (mirrors +HTTP3 / +WebSocket / +Chunked).
//
//  Merged-mailbox design (the fix for a residual cross-batch head-of-line block): a `reader` task owns
//  `connection.receive` in its own continuous loop, decoupled from every handler / native-streaming relay
//  / tunnel pump, feeding an `AsyncStream<HTTP2Wakeup>` mailbox; ONE sequential consumer (the `for await
//  wakeup in wakeups` loop below) is the SOLE reader/mutator of `engine` and the SOLE caller of
//  `connection.send`, applying each wakeup in turn. This mirrors HTTPServer+WebSocket.swift's existing
//  `driveWebSocket` / `pumpWebSocket` split — the identical problem, already solved there for one
//  connection's single WebSocket session — extended to HTTP/2's multiplexed stream + tunnel + native-
//  streaming-response event kinds.
//
//  What this fixes: the previous loop was `while true { events = engine.receive(inbound); [dispatch
//  non-request events inline]; withTaskGroup { spawn a child task per .request event IN THIS BATCH;
//  drain via for-await }; inbound = await connection.receive(...) for the NEXT batch }`. Structured
//  concurrency means that inner `withTaskGroup`'s closure could not return until every child task added
//  to it finished — so the NEXT batch was never read until every handler task from THIS batch was done.
//  Two requests arriving in separate TCP reads still serialized at the batch boundary (FIX #3 only won
//  concurrency WITHIN one batch, not across batches). A second, related bug: the old native-streaming
//  pump called `connection.receive()` ITSELF while a `.stream` response drained its send-window backlog,
//  so at most one native-streaming response was ever in flight per connection. Both bugs shared one root
//  cause: multiple things wanted to "own" reading from the connection. The merged mailbox below gives
//  reading exactly one owner (the reader task) and applying exactly one owner (the consumer), so the
//  NEXT inbound read is never gated behind ANY handler, relay, or tunnel pump — however many batches
//  those events originally arrived across.
//
//  IdleDeadline multiplexing: the passed-in `deadline` parameter now times ONLY the reader's receives —
//  unchanged from before this rewrite. The consumer's sends (a DIFFERENT, concurrently-running task now)
//  get their OWN local `IdleDeadline` (`sendDeadline` below) plus a small paired watchdog task; sharing
//  one `IdleDeadline` between the two would let either's `disarm()` silently cancel the other's in-flight
//  bound. Each native-streaming relay similarly gets its OWN third+ local `IdleDeadline` (see
//  HTTPServer+HTTP2Streaming.swift). This is intentional: many local `IdleDeadline` instances, each
//  timing exactly one caller's blocking calls with its own tiny watchdog — never one shared across
//  concurrently-running callers. A watchdog cannot capture this function's `DiscardingTaskGroup` (an
//  escaping closure cannot capture an `inout` parameter), so every local watchdog reports a lapse through
//  the SAME mailbox (`.localDeadlineLapsed`) instead of calling `cancelAll()` itself — only the consumer,
//  running non-escaping right here, ever calls it.
//

internal import HTTP2
internal import HTTPCore
internal import HTTPTransport
internal import WebSocket

extension HTTPServer {
    /// Drives the sans-I/O ``HTTP2Connection`` over `connection`: feed octets → events → respond →
    /// flush, until EOF, a timeout, or a connection-level protocol error. See the file comment for the
    /// merged-mailbox design this loop implements.
    func serveHTTP2(
        _ connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        initialBytes: [UInt8]
    ) async {
        // Advertise Extended CONNECT (RFC 8441 §3) only when the responder declares a WebSocket route.
        var settings = HTTP2Settings()
        settings.enableConnectProtocol = currentResolver?.hasWebSocketRoutes ?? false
        // The matched route's body limit, resolved from each request head before its DATA is buffered
        // (Phase 1.2); `nil` when the responder is not a router or the route declares no limit.
        let resolveBodyLimit: @Sendable (HTTPRequest) -> Int? = { [self] request in
            currentResolver?.resolve(method: request.method, path: request.path)?.bodyLimit
        }
        // Whether the matched route streams its request body (Phase 1.4) — the engine then surfaces the
        // body incrementally (requestHead/requestBodyChunk/requestEnd) instead of one buffered request.
        let resolveStreamsBody: @Sendable (HTTPRequest) -> Bool = { [self] request in
            currentResolver?.resolve(method: request.method, path: request.path)?.streamsBody
                ?? false
        }
        var engine = HTTP2Connection(
            localSettings: settings,
            limits: limits,
            resolveBodyLimit: resolveBodyLimit,
            resolveStreamsBody: resolveStreamsBody
        )
        // Per-stream WebSocket tunnels (RFC 8441) — just each tunnel's mailbox now; the engine + handler
        // live inside that tunnel's own pump task (HTTPServer+WebSocket.swift).
        var webSockets: [HTTP2StreamID: HTTP2WebSocketTunnel] = [:]
        // In-flight streaming-route requests (Phase 1.4): each feeds an incremental body stream the
        // handler consumes; its response arrives later as a `.requestReady` wakeup.
        var streaming: [HTTP2StreamID: HTTP2StreamingRequest] = [:]
        defer {
            // Connection closing: end every in-flight body stream so no handler stays parked reading one
            // that will never receive another chunk. The handler TASKS themselves are structured
            // children of the task group below, already reaped by its own teardown by the time this
            // runs — this is a defensive, now-mostly-symbolic mirror of that, kept for clarity.
            for pending in streaming.values {
                pending.continuation.finish()
            }
        }
        // Active native-streaming responses (P6b): each relay's pull-permission gate, keyed by stream.
        var relays: [HTTP2StreamID: HTTP2StreamPermit] = [:]
        var sentGoAway = false  // graceful shutdown queues GOAWAY once (RFC 9113 §6.8)
        // Dispatched-but-not-yet-reported handler / tunnel-pump tasks — see `.closed`'s handling below:
        // a request already fully received, or an open tunnel, needs no more INBOUND data to finish its
        // in-flight work, only the chance to actually run, so EOF must drain these before closing rather
        // than cancelling them out from under itself the instant the reader hits EOF.
        var pendingRequests = 0
        var pendingTunnels = 0
        // Set once the reader reports `.closed` — no more `.inbound` will ever follow. From then on,
        // every wakeup that could newly complete the drain (see `isDrained` below) re-checks it.
        var readerClosed = false

        let (wakeups, continuation) = AsyncStream.makeStream(
            of: HTTP2Wakeup.self, bufferingPolicy: .unbounded
        )
        // See the file comment: a SECOND, LOCAL idle deadline guards only this function's sends, now
        // that they run on a task separate from the reader.
        let sendDeadline = IdleDeadline<C.Instant>()
        // Whether every EOF-time obligation has cleared: no dispatched handler or tunnel pump is still
        // expected to report back, and no native-streaming relay is still active. Checked only once the
        // reader has actually closed — while it hasn't, `.inbound` keeps arriving and the connection has
        // no reason to close regardless of this being (transiently) true.
        func isDrained() -> Bool {
            readerClosed && pendingRequests == 0 && pendingTunnels == 0 && relays.isEmpty
        }

        await withDiscardingTaskGroup { group in
            // The reader: continuous, decoupled from every handler/relay/tunnel pump — the fix for the
            // residual cross-batch head-of-line block (see the file comment). Times its receives against
            // the ORIGINAL `deadline` parameter, unchanged from before this rewrite.
            group.addTask { [self] in
                await runHTTP2Reader(
                    connection, deadline: deadline, initialBytes: initialBytes, into: continuation
                )
            }
            // This consumer's own send-side watchdog (FIX #1 parity for the write side): reports a lapse
            // through the mailbox rather than calling `cancelAll()` directly (see the file comment).
            group.addTask { [self] in
                await runLocalIdleWatchdog(sendDeadline) { continuation.yield(.localDeadlineLapsed) }
            }

            for await wakeup in wakeups {
                switch wakeup {
                    case .inbound(let bytes):
                        let events: [HTTP2Connection.Event]
                        do {
                            events = try engine.receive(bytes)
                        }
                        catch {
                            // Connection-level protocol error: the engine queued a GOAWAY (RFC 9113 §6.8)
                            // — flush it best-effort so the peer learns the cause, then close.
                            _ = await flushHTTP2(&engine, to: connection, deadline: sendDeadline)
                            group.cancelAll()
                            return
                        }
                        for event in events {
                            handleHTTP2Event(
                                event,
                                engine: &engine,
                                connection: connection,
                                group: &group,
                                webSockets: &webSockets,
                                streaming: &streaming,
                                pendingRequests: &pendingRequests,
                                pendingTunnels: &pendingTunnels,
                                into: continuation
                            )
                        }
                        queueGoAwayIfDraining(&engine, &sentGoAway)  // RFC 9113 §6.8 graceful shutdown
                        if await flushHTTP2(&engine, to: connection, deadline: sendDeadline) {
                            group.cancelAll()
                            return
                        }
                        await releaseDrainedRelays(relays, engine: &engine)
                        if drainComplete(sentGoAway, engine) {
                            group.cancelAll()  // GOAWAY sent and all in-flight streams drained — close
                            return
                        }

                    case .requestReady(let streamID, let response):
                        pendingRequests -= 1
                        let fatal = beginHTTP2Response(
                            streamID: streamID,
                            response: response,
                            engine: &engine,
                            group: &group,
                            relays: &relays,
                            into: continuation
                        )
                        if await flushHTTP2(&engine, to: connection, deadline: sendDeadline) || fatal {
                            group.cancelAll()
                            return
                        }
                        await releaseDrainedRelays(relays, engine: &engine)
                        if isDrained() {
                            group.cancelAll()
                            return
                        }

                    case .streamChunk(let streamID, let item):
                        var fatal = false
                        switch item {
                            case .chunk(let bytes):
                                do {
                                    try engine.sendBodyChunk(to: streamID, bytes)
                                }
                                catch {
                                    relays.removeValue(forKey: streamID)
                                    fatal = true
                                }
                            case .finished:
                                relays.removeValue(forKey: streamID)
                                try? engine.endStream(to: streamID)
                            case .failed:
                                // RST_STREAM so the peer sees an incomplete response, not a clean
                                // truncation.
                                relays.removeValue(forKey: streamID)
                                do {
                                    try engine.abortResponse(to: streamID)
                                }
                                catch {
                                    // Reset budget exceeded (MadeYouReset parity, CVE-2025-8671) — the
                                    // engine already queued GOAWAY internally; flush + close.
                                    fatal = true
                                }
                        }
                        if await flushHTTP2(&engine, to: connection, deadline: sendDeadline) || fatal {
                            group.cancelAll()
                            return
                        }
                        await releaseDrainedRelays(relays, engine: &engine)
                        if isDrained() {
                            group.cancelAll()
                            return
                        }

                    case .tunnelOutbound(let streamID, let bytes):
                        engine.sendTunnelData(streamID, bytes)
                        if await flushHTTP2(&engine, to: connection, deadline: sendDeadline) {
                            group.cancelAll()
                            return
                        }

                    case .tunnelEnded(let streamID, let selfClosed):
                        pendingTunnels -= 1
                        // A peer-driven / connection-closing end already removed this tunnel from the map
                        // and told the engine nothing further (RFC 9113 §5.1 lets a closed/reset stream's
                        // id go); only a SELF-initiated close still needs `engine.closeTunnel` here.
                        webSockets.removeValue(forKey: streamID)
                        if selfClosed {
                            try? engine.closeTunnel(streamID)
                        }
                        if await flushHTTP2(&engine, to: connection, deadline: sendDeadline) {
                            group.cancelAll()
                            return
                        }
                        if isDrained() {
                            group.cancelAll()
                            return
                        }

                    case .closed:
                        // No more `.inbound` will ever arrive — but a request already fully received, an
                        // active relay, or an open tunnel needs no more of it to finish, only the chance
                        // to actually run (see the file comment and `HTTP2Wakeup.closed`'s doc). Abandon
                        // exactly the things that DO still need more input (a streaming-route request mid
                        // upload — matches the pre-rewrite behavior, which unconditionally tore down on
                        // EOF) and end every open tunnel (no more tunnel DATA can arrive either); then
                        // drain what is left before actually closing.
                        for pending in streaming.values {
                            pending.continuation.finish()
                        }
                        streaming.removeAll()
                        for tunnel in webSockets.values {
                            tunnel.mailbox.yield(.peerEnded)
                            tunnel.mailbox.finish()
                        }
                        webSockets.removeAll()
                        readerClosed = true
                        if isDrained() {
                            group.cancelAll()
                            return
                        }

                    case .localDeadlineLapsed:
                        // A local watchdog lapsed — a wedged consumer send or a wedged relay producer.
                        // Unlike `.closed`, this is NOT a graceful "let in-flight work finish" signal: it
                        // means something is actually stuck, so close immediately (FIX #1's original
                        // reap semantics — see HTTP2StreamPermit's / this file's comment on why a wedged
                        // relay's scope is the whole connection, not just its own stream).
                        group.cancelAll()
                        return
                }
            }
        }
    }

    /// The HTTP/2 reader: owns `connection.receive` in a continuous loop for the connection's whole life,
    /// decoupled from every handler/relay/tunnel task, feeding the merged mailbox. Never touches
    /// `engine` — only the consumer (the `for await wakeup in wakeups` loop in ``serveHTTP2``) does.
    ///
    /// Times its receives against `deadline` — the SAME parameter ``serveHTTP2`` was already passed, so
    /// the read-side Slowloris protection (RFC 9112 §9.3) is unchanged; the consumer's sends are timed
    /// against a separate, local deadline (see this file's comment) since the two now run concurrently.
    private func runHTTP2Reader(
        _ connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        initialBytes: [UInt8],
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async {
        if !initialBytes.isEmpty {
            continuation.yield(.inbound(initialBytes))
        }
        while true {
            deadline.arm(clock.now.advanced(by: limits.idleTimeout))
            let chunk = try? await connection.receive(maxLength: 16_384)
            deadline.disarm()
            guard let chunk, !chunk.isEmpty else {
                continuation.yield(.closed)  // EOF, idle timeout, or read failure
                return
            }
            continuation.yield(.inbound(chunk))
        }
    }
}
