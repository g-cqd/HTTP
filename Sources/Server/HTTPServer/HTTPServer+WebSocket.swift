//
//  HTTPServer+WebSocket.swift
//  HTTPServer
//
//  RFC 6455 §4 — the server's WebSocket integration: detect the Upgrade request, complete the
//  handshake (101 Switching Protocols), then drive the sans-I/O ``WebSocketConnection`` over the
//  transport for the connection's lifetime — reading frames, dispatching events to the application
//  handler, and flushing the frames it asks to send, until a Close, EOF, idle timeout, or I/O error.
//

internal import Foundation
internal import HTTP1
internal import HTTP2
internal import HTTPCore
internal import HTTPTransport
internal import WebSocket

extension HTTPServer {
    /// Whether `request` offers the `websocket` token in its `Upgrade` header (RFC 6455 §4.2.1).
    ///
    /// A routing pre-check only — ``WebSocketHandshake`` performs the strict §4.2.1 validation.
    static func isWebSocketUpgrade(_ request: HTTPRequest) -> Bool {
        for value in request.headerFields.values(for: .upgrade) {
            for token in value.split(separator: ",")
            where token.trimmingCharacters(in: .whitespaces).lowercased() == "websocket" {
                return true
            }
        }
        return false
    }

    /// Completes the opening handshake (RFC 6455 §4.2) and, on success, drives the connection; a
    /// malformed upgrade gets the rejection status (§4.4) and the connection is left to close.
    func serveWebSocket(
        _ connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        request: HTTPRequest,
        handler: any WebSocketHandler,
        hub: WebSocketHub?,
        topic: String?,
        carryover: [UInt8]
    ) async {
        // Cross-site WebSocket hijacking defense (RFC 6455 §10.2, CWE-1385): the handshake is exempt
        // from the Same-Origin Policy and CORS, so reject a disallowed Origin with 403 before
        // completing the upgrade. The default policy admits only a no-Origin (non-browser) client; apps
        // allowlist trusted browser origins via the handler.
        guard handler.isOriginAllowed(request.headerFields[.origin]) else {
            let rejection = ResponseSerializer.serialize(HTTPResponse(status: .forbidden))
            try? await connection.send(rejection)
            return
        }
        let accepted: HTTPResponse
        do {
            accepted = try WebSocketHandshake.response(to: request)
        }
        catch {
            let rejection = ResponseSerializer.serialize(
                HTTPResponse(status: error.rejectionStatus)
            )
            try? await connection.send(rejection)
            return
        }
        guard (try? await connection.send(ResponseSerializer.serialize(accepted))) != nil else {
            return
        }
        // The 101 already echoed permessage-deflate when offered; enable it on the engine too (§5.1).
        let permessageDeflate = WebSocketHandshake.negotiatePermessageDeflate(request.headerFields)
        await driveWebSocket(
            connection,
            deadline: deadline,
            handler: handler,
            hub: hub,
            topic: topic,
            carryover: carryover,
            permessageDeflate: permessageDeflate
        )
    }

    /// Pumps the ``WebSocketConnection`` over `connection` until a Close, EOF, idle timeout, or send
    /// failure (RFC 6455 §6).
    ///
    /// A reader task feeds inbound bytes, and a hub (Phase 2.7) feeds broadcasts, to the pump — so the
    /// server can push a frame without the pump blocking on `receive`. The two travel by *different*
    /// routes because they need opposite policies (2026-07-31 audit, finding 1): transport octets go
    /// through a lossless, byte-watermarked ``BoundedByteChannel`` that parks the reader — and so
    /// closes the peer's TCP window — while broadcasts go through a bounded ``WebSocketBroadcastMailbox``
    /// with a counted drop. Only payload-free tickets travel on the ``WebSocketWakeup`` stream itself.
    private func driveWebSocket(
        _ connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        handler: any WebSocketHandler,
        hub: WebSocketHub?,
        topic: String?,
        carryover: [UInt8],
        permessageDeflate: PermessageDeflateParameters?
    ) async {
        // The frame cap rides the message cap: a single frame can never legitimately exceed the
        // message it belongs to, so a smaller standalone frame default would spuriously reject
        // cap-legal unfragmented messages (RFC 6455 §5.4 — Autobahn 9.1/9.2 send up to 16 MiB in
        // one frame).
        var engine = WebSocketConnection(
            maxFrameSize: limits.effectiveWebSocketMessageSize,
            maxMessageSize: limits.effectiveWebSocketMessageSize,
            permessageDeflate: permessageDeflate
        )
        // `.unbounded` is safe here precisely because the payloads moved out: an inbound ticket is 1:1
        // with a chunk the channel caps at `maxQueuedInboundChunks`, and the broadcast edge is
        // coalesced to one outstanding ticket. See WebSocketWakeup.swift.
        let (wakeups, continuation) = AsyncStream.makeStream(
            of: WebSocketWakeup.self, bufferingPolicy: .unbounded
        )
        let intake = BoundedByteChannel(
            highWatermark: limits.maxQueuedInboundBytes,
            lowWatermark: limits.maxQueuedInboundBytes / 2,
            maxQueuedChunks: limits.maxQueuedInboundChunks,
            coalescingBelow: 4 * 1_024
        )
        let broadcasts = WebSocketBroadcastMailbox(capacity: limits.maxQueuedBroadcasts)
        // Lifecycle hook: the upgrade is complete — let the handler speak first (a greeting/hello),
        // before any peer frame or broadcast is delivered.
        for action in await handler.onOpen() { engine.apply(action) }
        let greeting = engine.outboundBytes()
        if !greeting.isEmpty, (try? await connection.send(greeting)) == nil {
            await handler.onClose()
            await connection.close()
            return
        }
        // Hub (Phase 2.7): register this connection's broadcast sink and auto-subscribe it to the topic,
        // so a published message arrives as a `.broadcast` wakeup, applied to the engine below.
        var token: UInt64?
        if let hub, let topic {
            token = await hub.register { message in
                // The `deposit` outcome is the inspected result the audit requires: an evicted
                // broadcast is counted, and the pump turns a non-zero count into a 1008 close rather
                // than silently serving the peer an incomplete view of the topic.
                broadcasts.deposit(message) { continuation.yield(.broadcastReady) }
            }
            if let token { await hub.subscribe(token, to: topic) }
        }
        // Reader: feed the carryover, then inbound bytes (timed by the idle deadline), into the
        // lossless intake channel, yielding exactly one ticket per item.
        let reader = Task {
            if !carryover.isEmpty, await intake.send(carryover) == .queued {
                continuation.yield(.inboundReady)
            }
            while !Task.isCancelled {
                deadline.arm(clock.now.advanced(by: limits.keepAliveTimeout))
                let chunk = try? await connection.receive(maxLength: 16_384)
                deadline.disarm()
                guard let chunk, !chunk.isEmpty else {
                    break  // EOF, idle timeout, or read failure
                }
                // Arm around the handoff too. While the reader is parked waiting for the pump to
                // drain, no receive is outstanding, so without this the connection watchdog would nap
                // and re-check forever and a permanently wedged handler would hold the connection
                // open indefinitely. A merely *slow* handler re-arms on each chunk and is not reaped.
                deadline.arm(clock.now.advanced(by: limits.idleTimeout))
                let outcome = await intake.send(chunk)
                deadline.disarm()
                // One ticket per QUEUED item only: a coalesced send extended an item whose ticket is
                // still outstanding, and a second ticket for it would park the pump in `intake.next()`.
                if outcome == .queued {
                    continuation.yield(.inboundReady)
                }
            }
            await intake.finish()
            continuation.yield(.inboundReady)  // the ticket that delivers the terminal item
        }
        await pumpWebSocket(
            wakeups,
            intake: intake,
            broadcasts: broadcasts,
            engine: &engine,
            handler: handler,
            connection: connection
        )
        reader.cancel()
        await intake.abandon()  // unblocks a reader parked in `send` so the task actually exits
        continuation.finish()
        if let hub, let token { await hub.remove(token) }
        await connection.close()
        // Lifecycle hook: the session is over — every ending funnels through here exactly once
        // (clean Close handshake, abrupt EOF, idle timeout, send failure).
        await handler.onClose()
    }

    /// Consumes the wakeup stream: receive → events → handler actions, or a hub broadcast → send; flushes
    /// after each, stopping on a queued Close, the reader closing, or a send failure (RFC 6455 §6).
    private func pumpWebSocket(
        _ wakeups: AsyncStream<WebSocketWakeup>,
        intake: BoundedByteChannel,
        broadcasts: WebSocketBroadcastMailbox,
        engine: inout WebSocketConnection,
        handler: any WebSocketHandler,
        connection: any TransportConnection
    ) async {
        for await wakeup in wakeups {
            let ended =
                switch wakeup {
                    case .inboundReady:
                        await applyInbound(intake, engine: &engine, handler: handler)
                    case .broadcastReady:
                        applyBroadcasts(broadcasts, engine: &engine)
                }
            let outbound = engine.outboundBytes()
            if !outbound.isEmpty, (try? await connection.send(outbound)) == nil {
                return
            }
            if ended || engine.isClosing {
                return
            }
        }
    }

    /// Takes the one chunk this ticket accounts for and drives it through the engine and handler.
    ///
    /// The matching ``BoundedByteChannel/next()`` cannot suspend: the reader yields exactly one ticket
    /// per queued item, so an item is always already there.
    ///
    /// - Returns: whether the session has ended (a protocol violation left a queued Close, or the
    ///   producer reached EOF / was abandoned).
    private func applyInbound(
        _ intake: BoundedByteChannel,
        engine: inout WebSocketConnection,
        handler: any WebSocketHandler
    ) async -> Bool {
        switch await intake.next() {
            case .chunk(let bytes):
                do {
                    for event in try engine.receive(bytes) {
                        for action in await handler.handle(event) { engine.apply(action) }
                    }
                }
                catch {
                    return true  // the engine queued a Close; the caller flushes it, then stops
                }
                return false
            case .finished, .aborted:
                return true
        }
    }

    /// Drains every queued broadcast into the engine, closing the session if any were evicted.
    ///
    /// A connection that could not keep up is closed with `1008` (RFC 6455 §7.4.1) rather than left
    /// with a silent hole in its view of the topic — the explicit disconnect half of the bounded
    /// drop policy.
    private func applyBroadcasts(
        _ broadcasts: WebSocketBroadcastMailbox,
        engine: inout WebSocketConnection
    ) -> Bool {
        for message in broadcasts.drain() {
            switch message {
                case .text(let string):
                    engine.apply(.sendText(string))
                case .binary(let bytes):
                    engine.apply(.sendBinary(bytes))
            }
        }
        guard broadcasts.droppedCount > 0 else {
            return false
        }
        engine.apply(.close(.policyViolation, reason: "broadcast backlog exceeded"))
        return true
    }

    // MARK: WebSocket over HTTP/2 (RFC 8441 / RFC 9220)

    /// Dispatches a tunnel event from the HTTP/2 engine for a WebSocket-over-HTTP/2 stream: accept an
    /// Extended CONNECT (RFC 8441 §4) and spin up this tunnel's dedicated pump task, relay tunnel DATA to
    /// it, or tell it the peer ended the tunnel.
    ///
    /// Every ENGINE mutation (`acceptTunnel` here; `sendTunnelData` / `closeTunnel` later, when the
    /// consumer processes this tunnel's `.tunnelOutbound` / `.tunnelEnded` wakeup) stays on the consumer.
    /// The pump task — spun up below — only ever touches its OWN per-tunnel WebSocket engine and the
    /// route handler, reporting back through `continuation`, so a slow WebSocket-over-h2 handler no
    /// longer head-of-line-blocks any other stream multiplexed on this connection (this path was not
    /// covered by the existing FIX #3, which only dispatched buffered-request handlers).
    ///
    /// `pendingTunnels` counts dispatched-but-not-yet-`.tunnelEnded` pump tasks, incremented here on
    /// dispatch — the consumer's EOF drain check (``HTTPServer/serveHTTP2(_:deadline:initialBytes:)``'s
    /// `.closed` case) reads it to know whether a tunnel might still have in-flight work worth letting
    /// finish before the connection actually closes.
    func handleHTTP2Tunnel(
        _ event: HTTP2Connection.Event,
        state: inout HTTP2ConnectionState,
        group: inout DiscardingTaskGroup,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async {
        switch event {
            case .extendedConnect(let streamID, let request, let proto):
                // Resolve the WebSocket route for this stream's path; an Extended CONNECT to a path the
                // responder does not declare a WebSocket route for is refused (no tunnel opened). Same
                // CSWSH defense as the h1 path (RFC 6455 §10.2): a disallowed Origin refuses the tunnel,
                // treated like a declined upgrade.
                guard proto == "websocket",
                    let handler = currentResolver?
                        .resolveWebSocket(path: request.path)?
                        .webSocketHandler,
                    handler.shouldUpgrade(request),
                    handler.isOriginAllowed(request.headerFields[.origin])
                else { return }
                // Negotiate permessage-deflate over the RFC 8441 tunnel: echo it on the 200 and enable
                // it on the engine when the Extended CONNECT offered it (RFC 7692 §5.1 / RFC 9220).
                let permessageDeflate = WebSocketHandshake.negotiatePermessageDeflate(
                    request.headerFields
                )
                try? state.engine.acceptTunnel(  // 200, no END_STREAM (RFC 8441 §5)
                    streamID,
                    secWebSocketExtensions: permessageDeflate?.headerValue
                )
                // Consumption-gated, exactly like a streaming-route body (audit F2): the peer may run at
                // most one `streamReceiveWindow` ahead of this tunnel's handler, and the window re-opens
                // only as the pump reports what it has processed.
                let channel = makeHTTP2GatedChannel()
                let signal = HTTP2ConsumptionSignal { continuation.yield(.consumed(streamID)) }
                state.consumption[streamID] = signal
                state.webSockets[streamID] = HTTP2WebSocketTunnel(channel: channel, signal: signal)
                state.pendingTunnels += 1
                group.addTask { [self] in
                    await runHTTP2Tunnel(
                        streamID: streamID,
                        handler: handler,
                        permessageDeflate: permessageDeflate,
                        channel: channel,
                        signal: signal,
                        into: continuation
                    )
                }
            case .tunnelData(let streamID, let bytes):
                await pushHTTP2TunnelData(streamID, bytes: bytes, state: &state)
            case .tunnelClosed(let streamID):
                // Exactly-once: only a tunnel still tracked is ended here (a self-closed removal — see
                // `.tunnelEnded` in HTTPServer+HTTP2Wakeups.swift — has already removed it). `finish()`
                // rather than `abandon()`, so frames already in flight are still delivered before the
                // pump sees the end. The pump reports back via `.tunnelEnded`, so `pendingTunnels` (not
                // this map) is what the EOF drain check waits on.
                if let tunnel = state.webSockets.removeValue(forKey: streamID) {
                    await tunnel.channel.finish()
                }
            default:
                break
        }
    }

    /// Hands one decoded tunnel DATA chunk to its pump — never blocking the consumer (RFC 8441 §5).
    ///
    /// Same discipline as a streaming-route body chunk: `trySend`, because the consumer owns the engine
    /// and must stay free to process the WINDOW_UPDATE that unblocks the connection. A refusal ends the
    /// tunnel rather than dropping a frame — a WebSocket stream is a resumable parser, so a dropped
    /// chunk would desynchronize framing rather than merely lose data (RFC 6455 §5).
    private func pushHTTP2TunnelData(
        _ streamID: HTTP2StreamID,
        bytes: [UInt8],
        state: inout HTTP2ConnectionState
    ) async {
        guard let tunnel = state.webSockets[streamID] else {
            return  // already closed or reset out from under this chunk
        }
        guard await tunnel.channel.trySend(bytes) != .refused else {
            await endHTTP2Stream(streamID, resettingWith: .flowControlError, state: &state)
            return
        }
    }

    /// Pumps one WebSocket-over-HTTP/2 tunnel's whole lifetime (RFC 8441 §5 / RFC 6455 §6): its own
    /// sans-I/O ``WebSocketConnection`` and the route's ``WebSocketHandler`` live ONLY here, in this task,
    /// for as long as the tunnel is open — never touched by the consumer — so this tunnel's traffic never
    /// races another stream's, and a permessage-deflate context-takeover window is never corrupted by
    /// out-of-order completion (the hazard of instead dispatching each tunnel DATA event to its own
    /// throwaway task: two such tasks could apply their handler's actions — and so their compressor /
    /// decompressor state — out of arrival order).
    ///
    /// Exactly-once lifecycle hooks (RFC 6455 §7): `onOpen` before the first byte is processed; `onClose`
    /// exactly once, right here, as this function returns — for every ending, whether the local engine
    /// decided to close, the peer ended the tunnel, or the connection is tearing down (``
    /// BoundedByteChannel/next()`` is cancellation-aware and resumes `.aborted`, so a cancelled pump
    /// unwinds exactly like a normal completion). `.tunnelEnded` is likewise yielded UNCONDITIONALLY on
    /// every exit — including a cancelled one — so the consumer's `pendingTunnels` count (the EOF drain
    /// check) always reaches zero and the connection is never held open waiting on a pump task that has
    /// actually already finished.
    ///
    /// Consumption is reported AFTER the handler has been driven over the chunk, not when it is taken
    /// off the channel: that is what makes the peer's window track the handler's real progress rather
    /// than the pump's willingness to dequeue (audit F2).
    private func runHTTP2Tunnel(
        streamID: HTTP2StreamID,
        handler: any WebSocketHandler,
        permessageDeflate: PermessageDeflateParameters?,
        channel: BoundedByteChannel,
        signal: HTTP2ConsumptionSignal,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async {
        var socket = WebSocketConnection(
            // Frame cap = message cap, as on the h1 path (a frame cannot exceed its message).
            maxFrameSize: limits.effectiveWebSocketMessageSize,
            maxMessageSize: limits.effectiveWebSocketMessageSize,
            permessageDeflate: permessageDeflate
        )
        // Lifecycle hook: the tunnel is open — let the handler speak first.
        for action in await handler.onOpen() { socket.apply(action) }
        let greeting = socket.outboundBytes()
        if !greeting.isEmpty { continuation.yield(.tunnelOutbound(streamID, greeting)) }

        var selfClosed = false
        while case .chunk(let bytes) = await channel.next() {
            // A violation leaves a queued Close and sets `isClosing`; handled below.
            let events = (try? socket.receive(bytes)) ?? []
            for event in events {
                for action in await handler.handle(event) { socket.apply(action) }
            }
            let outbound = socket.outboundBytes()
            if !outbound.isEmpty { continuation.yield(.tunnelOutbound(streamID, outbound)) }
            // The handler has now seen everything in this chunk, so the octets are genuinely consumed
            // and the peer may be given that much window back (RFC 9113 §6.9).
            signal.record(bytes.count)
            if socket.isClosing {
                selfClosed = true
                break
            }
        }
        await handler.onClose()  // lifecycle hook — the session is over, exactly once
        continuation.yield(.tunnelEnded(streamID, selfClosed: selfClosed))
    }
}
