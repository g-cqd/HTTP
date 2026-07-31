//
//  HTTPServer+HTTP2Wakeups.swift
//  HTTPServer
//
//  One small function per ``HTTP2Wakeup`` kind, plus the dispatcher the serve loop calls.
//
//  Split out of HTTPServer+HTTP2.swift, where the equivalent code was a single 134-line closure at
//  cyclomatic complexity 29 — over both configured limits, and the reason `swiftlint --strict` was red
//  on the branch. Behavior is unchanged by the split itself; the inbound path additionally moves to the
//  bounded intake channel (2026-07-31 audit, finding 3).
//
//  Every function here runs on the consumer, which is the sole owner of the engine and of
//  `connection.send`. Each returns whether the connection must now close, so the caller does the one
//  `cancelAll()` in one place.
//

internal import HTTP2
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Applies one wakeup.
    ///
    /// - Returns: whether the connection must close.
    func applyHTTP2Wakeup(
        _ wakeup: HTTP2Wakeup,
        state: inout HTTP2ConnectionState,
        group: inout DiscardingTaskGroup,
        connection: any TransportConnection,
        intake: BoundedByteChannel,
        sendDeadline: IdleDeadline<C.Instant>,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async -> Bool {
        switch wakeup {
            case .inboundReady:
                await applyInboundReady(
                    state: &state,
                    group: &group,
                    connection: connection,
                    intake: intake,
                    sendDeadline: sendDeadline,
                    into: continuation
                )
            case .requestReady(let streamID, let response):
                await applyRequestReady(
                    streamID,
                    response: response,
                    state: &state,
                    group: &group,
                    connection: connection,
                    sendDeadline: sendDeadline,
                    into: continuation
                )
            case .streamChunk(let streamID, let item):
                await applyStreamChunk(
                    streamID,
                    item: item,
                    state: &state,
                    connection: connection,
                    sendDeadline: sendDeadline
                )
            case .consumed(let streamID):
                await applyConsumed(
                    streamID,
                    state: &state,
                    connection: connection,
                    sendDeadline: sendDeadline
                )
            case .tunnelOutbound(let streamID, let bytes):
                await applyTunnelOutbound(
                    streamID,
                    bytes: bytes,
                    state: &state,
                    connection: connection,
                    sendDeadline: sendDeadline
                )
            case .tunnelEnded(let streamID, let selfClosed):
                await applyTunnelEnded(
                    streamID,
                    selfClosed: selfClosed,
                    state: &state,
                    connection: connection,
                    sendDeadline: sendDeadline
                )
            case .sweepStalls:
                await applySweepStalls(
                    state: &state,
                    connection: connection,
                    sendDeadline: sendDeadline
                )
            case .localDeadlineLapsed:
                // A wedged consumer send or a wedged relay producer. Unlike end-of-input this is not a
                // graceful "let in-flight work finish" signal — something is actually stuck, so close.
                true
        }
    }

    /// Takes the one intake item this ticket accounts for and drives it through the engine.
    ///
    /// The matching ``BoundedByteChannel/next()`` cannot suspend: the reader yields exactly one ticket
    /// per queued item. End-of-input now arrives *in band* here rather than as a separate wakeup, which
    /// also removes an ordering hazard — the old `.closed` case raced `.inbound` through the same
    /// mailbox and was only accidentally ordered correctly.
    private func applyInboundReady(
        state: inout HTTP2ConnectionState,
        group: inout DiscardingTaskGroup,
        connection: any TransportConnection,
        intake: BoundedByteChannel,
        sendDeadline: IdleDeadline<C.Instant>,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async -> Bool {
        switch await intake.next() {
            case .chunk(let bytes):
                return await applyInboundChunk(
                    bytes,
                    state: &state,
                    group: &group,
                    connection: connection,
                    sendDeadline: sendDeadline,
                    into: continuation
                )
            case .finished, .aborted:
                // No more octets will ever arrive — but a request already fully received, an active
                // relay, or an open tunnel needs none to finish, only the chance to run. Abandon exactly
                // the things that DO still need input (a streaming-route body mid-upload), end every
                // tunnel, then drain what is left before actually closing.
                await state.finishAllStreaming()
                await state.endAllTunnels()
                state.readerClosed = true
                return state.isDrained
        }
    }

    private func applyInboundChunk(
        _ bytes: [UInt8],
        state: inout HTTP2ConnectionState,
        group: inout DiscardingTaskGroup,
        connection: any TransportConnection,
        sendDeadline: IdleDeadline<C.Instant>,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async -> Bool {
        let events: [HTTP2Connection.Event]
        do {
            events = try state.engine.receive(bytes)
        }
        catch {
            // Connection-level protocol error: the engine queued a GOAWAY (RFC 9113 §6.8) — flush it
            // best-effort so the peer learns the cause, then close.
            _ = await flushHTTP2(&state.engine, to: connection, deadline: sendDeadline)
            return true
        }
        for event in events {
            await handleHTTP2Event(
                event,
                state: &state,
                connection: connection,
                group: &group,
                into: continuation
            )
        }
        queueGoAwayIfDraining(&state.engine, &state.sentGoAway)  // RFC 9113 §6.8 graceful shutdown
        if await flushHTTP2(&state.engine, to: connection, deadline: sendDeadline) {
            return true
        }
        await releaseDrainedRelays(state.relays, engine: &state.engine)
        // GOAWAY sent and every in-flight stream drained — close.
        return drainComplete(state.sentGoAway, state.engine)
    }

    /// Credits a gated stream's receive windows for what its handler has consumed (RFC 9113 §6.9).
    ///
    /// The loop's half of the gate: the handler reported into a lock-free counter and poked the mailbox,
    /// and only here — on the engine's single owner — is that report turned into a WINDOW_UPDATE.
    /// Flushing immediately matters: the peer is stalled on a closed window until those octets reach it,
    /// so batching this behind unrelated work would show up directly as upload latency.
    private func applyConsumed(
        _ streamID: HTTP2StreamID,
        state: inout HTTP2ConnectionState,
        connection: any TransportConnection,
        sendDeadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        // A report can outlive its stream (the handler drained a last chunk as the peer reset it); the
        // credit was already returned wholesale by `retire`, so there is nothing left to do.
        guard let consumed = state.consumption[streamID]?.takeAll(), consumed > 0 else {
            return false
        }
        state.engine.replenishReceiveWindow(streamID, consumed: consumed)
        state.noteConsumption(streamID)  // byte progress — this stream is not stalling
        return await flushHTTP2(&state.engine, to: connection, deadline: sendDeadline)
    }

    /// Resets every gated stream that has held receive credit across two sweeps without consuming any.
    ///
    /// The price of consumption gating, paid deliberately. Replenishment now depends on the
    /// application, so a handler that stops reading holds part of the *shared* connection window and
    /// slows every sibling stream on the connection. That is HTTP/2's own semantics rather than a defect
    /// — one connection, one window — but leaving it unbounded would turn a single wedged handler into a
    /// connection-wide denial of service. ENHANCE_YOUR_CALM (RFC 9113 §7) names the condition exactly:
    /// the peer is behaving correctly, the server simply cannot keep up with this stream.
    ///
    /// Surgical by design: only the offending stream is reset and its siblings keep running, which is
    /// what distinguishes this from the connection-fatal `.localDeadlineLapsed` watchdogs.
    private func applySweepStalls(
        state: inout HTTP2ConnectionState,
        connection: any TransportConnection,
        sendDeadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        let stalled = state.sweepStalls()
        guard !stalled.isEmpty else {
            return false
        }
        for streamID in stalled {
            await endHTTP2Stream(streamID, resettingWith: .enhanceYourCalm, state: &state)
        }
        if await flushHTTP2(&state.engine, to: connection, deadline: sendDeadline) {
            return true
        }
        return state.isDrained
    }

    private func applyRequestReady(
        _ streamID: HTTP2StreamID,
        response: ServerResponse,
        state: inout HTTP2ConnectionState,
        group: inout DiscardingTaskGroup,
        connection: any TransportConnection,
        sendDeadline: IdleDeadline<C.Instant>,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async -> Bool {
        state.dispatched.remove(streamID)
        // The handler has returned, so nothing more will ever consume this stream's body. Hand back
        // whatever it left untaken BEFORE responding — `engine.respond` may close and drop the stream,
        // and credit not returned by then is credit the connection loses for good (§6.9.1).
        state.retire(streamID)
        let fatal = beginHTTP2Response(
            streamID: streamID,
            response: response,
            engine: &state.engine,
            group: &group,
            relays: &state.relays,
            into: continuation
        )
        if await flushHTTP2(&state.engine, to: connection, deadline: sendDeadline) || fatal {
            return true
        }
        await releaseDrainedRelays(state.relays, engine: &state.engine)
        return state.isDrained
    }

    private func applyStreamChunk(
        _ streamID: HTTP2StreamID,
        item: AsyncHandoff.Item,
        state: inout HTTP2ConnectionState,
        connection: any TransportConnection,
        sendDeadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        var fatal = false
        switch item {
            case .chunk(let bytes):
                do {
                    try state.engine.sendBodyChunk(to: streamID, bytes)
                }
                catch {
                    state.relays.removeValue(forKey: streamID)
                    fatal = true
                }
            case .finished:
                state.relays.removeValue(forKey: streamID)
                try? state.engine.endStream(to: streamID)
            case .failed:
                // RST_STREAM so the peer sees an incomplete response, not a clean truncation.
                state.relays.removeValue(forKey: streamID)
                do {
                    try state.engine.abortResponse(to: streamID)
                }
                catch {
                    // Reset budget exceeded (MadeYouReset parity, CVE-2025-8671) — the engine already
                    // queued GOAWAY internally; flush and close.
                    fatal = true
                }
        }
        if await flushHTTP2(&state.engine, to: connection, deadline: sendDeadline) || fatal {
            return true
        }
        await releaseDrainedRelays(state.relays, engine: &state.engine)
        return state.isDrained
    }

    private func applyTunnelOutbound(
        _ streamID: HTTP2StreamID,
        bytes: [UInt8],
        state: inout HTTP2ConnectionState,
        connection: any TransportConnection,
        sendDeadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        state.engine.sendTunnelData(streamID, bytes)
        return await flushHTTP2(&state.engine, to: connection, deadline: sendDeadline)
    }

    private func applyTunnelEnded(
        _ streamID: HTTP2StreamID,
        selfClosed: Bool,
        state: inout HTTP2ConnectionState,
        connection: any TransportConnection,
        sendDeadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        state.pendingTunnels -= 1
        // A peer-driven or connection-closing end already removed this tunnel from the map and told the
        // engine nothing further (RFC 9113 §5.1 lets a closed/reset stream's id go); only a SELF-
        // initiated close still needs `engine.closeTunnel` here.
        state.webSockets.removeValue(forKey: streamID)
        // The pump has finished, so nothing more will ever consume this tunnel's inbound: give back any
        // credit it was still holding before the engine drops the stream (RFC 9113 §6.9.1).
        state.retire(streamID)
        if selfClosed {
            try? state.engine.closeTunnel(streamID)
        }
        if await flushHTTP2(&state.engine, to: connection, deadline: sendDeadline) {
            return true
        }
        return state.isDrained
    }
}
