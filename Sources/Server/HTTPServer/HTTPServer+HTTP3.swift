//
//  HTTPServer+HTTP3.swift
//  HTTPServer
//
//  RFC 9114 — the HTTP/3 half of the server runtime, mirroring `serveHTTP2`'s
//  receive → events → respond → flush loop but over QUIC. QUIC delivers bytes per stream, so a
//  connection's streams are served concurrently; the non-Sendable sans-I/O ``HTTP3Connection`` engine
//  is serialized behind an `actor`. At connection start the server opens its control + QPACK
//  unidirectional streams (the engine's queued ``HTTP3Connection/Action/openUniStream(role:preamble:)``
//  actions, RFC 9114 §6.2 / §3.2); each inbound request stream is then fed to the engine, the resulting
//  request handed to the responder, and the response flushed back on that stream.
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport
internal import Synchronization
internal import WebSocket

extension HTTPServer {
    /// Serializes the non-`Sendable` ``HTTP3Connection`` engine across a connection's concurrent streams.
    actor Engine {
        private var connection: HTTP3Connection
        /// The server's own unidirectional streams by role (control / QPACK encoder+decoder), so
        /// role-addressed engine sends — QPACK Insert Count Increment / Section Acknowledgment on the
        /// decoder stream (RFC 9204 §4.4) — reach the right stream.
        private var roleStreams: [HTTP3StreamRole: any QUICStream] = [:]

        init(
            limits: HTTPLimits,
            enableConnectProtocol: Bool,
            resolveRoute: @escaping @Sendable (QUICStreamID, HTTPRequest) -> RequestBodyPolicy
        ) {
            var settings = HTTP3Settings()
            settings.enableConnectProtocol = enableConnectProtocol  // RFC 9220 — WebSocket over h3
            connection = HTTP3Connection(
                localSettings: settings,
                limits: limits,
                resolveRoute: resolveRoute
            )
        }

        /// Records a freshly opened server uni stream so later role-addressed sends can find it.
        func attachRoleStream(_ role: HTTP3StreamRole, _ stream: any QUICStream) {
            roleStreams[role] = stream
        }

        /// Sends `bytes` on the stream opened for `role` (a no-op if it is not open yet).
        func sendOnRole(_ role: HTTP3StreamRole, _ bytes: [UInt8], fin: Bool) async {
            guard let stream = roleStreams[role] else {
                return
            }
            try? await stream.send(bytes, fin: fin)
        }

        /// The actions queued so far (the init-time control/QPACK stream openers, then drained).
        func pendingActions() -> [HTTP3Connection.Action] {
            connection.outbound()
        }

        /// Feeds one stream's bytes and files everything they surfaced for *other* streams (R5-P0b).
        ///
        /// A connection error is swallowed; its CONNECTION_CLOSE is queued among the returned actions.
        ///
        /// The routing happens here, inside the actor, rather than in the caller after this returns.
        /// Engine output is addressed by stream id and need not belong to the stream whose bytes
        /// provoked it — RFC 9204 §2.1.2, where an encoder-stream insert unblocks a *request* stream's
        /// field section — and clearing that stream's blocked state is part of the very call that
        /// produces its `request` event. Handing the batch back for the caller to file left those two
        /// facts separated by a suspension point, so a concurrent
        /// ``endDriving(_:registry:)`` could observe "no longer blocked" while the event was still in
        /// flight and retire the entry it was about to be delivered to. Filing under the same isolation
        /// makes the ordering a property of *where* the code runs rather than of how two tasks
        /// interleaved: no third state exists between the two.
        func receive(
            _ id: QUICStreamID,
            _ bytes: [UInt8],
            fin: Bool,
            routingInto registry: HTTP3StreamRegistry
        ) -> HTTP3Reception {
            let produced = (try? connection.receive(id, bytes, fin: fin)) ?? []
            let routed = registry.route(produced, owner: id)
            return HTTP3Reception(
                own: routed.own,
                actions: connection.outbound(),
                overflowed: routed.overflowed
            )
        }

        /// Encodes a response on `id` and returns the queued send/close actions.
        func respond(
            to id: QUICStreamID, _ response: HTTPResponse, body: [UInt8]
        ) -> [HTTP3Connection.Action] {
            try? connection.respond(to: id, response, body: body)
            return connection.outbound()
        }

        /// Encodes a *streaming* response's HEADERS on `id` (no FIN), untracking the stream.
        ///
        /// Returns the frame bytes for the driver to send and FIN itself, or nil if the engine rejects
        /// it (an unknown stream — not expected for a just-emitted request). The body DATA + FIN follow
        /// off-actor, framed by ``HTTP3Connection/dataFrame(_:)``.
        func respondHeaders(to id: QUICStreamID, _ head: HTTPResponse) -> [UInt8]? {
            try? connection.respondHeaders(to: id, head)
        }

        /// Accepts an Extended CONNECT tunnel (RFC 9220), returning the `200` HEADERS bytes for the
        /// driver to send `fin:false`; nil if the engine rejects it (unknown / non-tunnel stream).
        func acceptTunnel(_ id: QUICStreamID, secWebSocketExtensions: String?) -> [UInt8]? {
            try? connection.acceptTunnel(id, secWebSocketExtensions: secWebSocketExtensions)
        }

        /// Frames `bytes` as a tunnel DATA frame (RFC 9220) for the driver to send on the stream.
        func sendTunnelData(_ id: QUICStreamID, _ bytes: [UInt8]) -> [UInt8] {
            connection.sendTunnelData(id, bytes)
        }

        /// Untracks a tunnel stream (RFC 9220); the driver sends the FIN to close it.
        func closeTunnel(_ id: QUICStreamID) {
            connection.closeTunnel(id)
        }

        /// Ends the driving phase for `id`, keeping its entry only while something is owed.
        ///
        /// The two halves of that decision — "does the engine still hold a QPACK-blocked field section
        /// for this stream" (RFC 9204 §2.1.2) and "is the registry about to drop the entry" — are made
        /// in one actor-isolated step, and every routed deposit is made in the *same* isolation by
        /// ``receive(_:_:fin:routingInto:)``. So the check and the delivery cannot interleave: either
        /// the deposit ran first and the registry sees a non-empty mailbox, or it has not run yet and
        /// the engine still reports the section blocked. There is no window in which both say no.
        ///
        /// - Returns: whether the entry was kept, for the connection dispatcher to answer on.
        func endDriving(_ id: QUICStreamID, registry: HTTP3StreamRegistry) -> Bool {
            registry.endDriving(id, retain: connection.isBlocked(id))
        }

        /// Retires the engine state behind `id` and returns the actions to flush (audit REG-3).
        ///
        /// The engine is sans-I/O: resetting a QUIC stream on the wire tells it nothing, so without
        /// this call it keeps the stream's parser buffer, its decoded request, its buffered body, and
        /// its slot in the SETTINGS_QPACK_BLOCKED_STREAMS allowance (RFC 9204 §2.1.2) for the life of
        /// the connection. ``HTTP3Connection/resetStream(_:errorCode:)`` is the entry point rather than
        /// a fresh partial cleanup precisely because it also charges the RFC 9114 §8.1 rolling reset
        /// budget — a stream the peer abandons has to cost it something, or repeating it is free.
        func retire(_ id: QUICStreamID, errorCode: UInt64) -> [HTTP3Connection.Action] {
            _ = connection.resetStream(id, errorCode: errorCode)
            return connection.outbound()
        }

        /// What the engine still retains for this connection (audit REG-3 observability).
        func census() -> HTTP3ConnectionCensus {
            connection.census
        }

        /// Queues the graceful-shutdown GOAWAY (RFC 9114 §5.2) and returns the actions to flush.
        func beginGracefulShutdown() -> [HTTP3Connection.Action] {
            connection.beginGracefulShutdown()
            return connection.outbound()
        }
    }

    /// Runs the QUIC listener: advertise `Alt-Svc` (RFC 7838), then serve each connection as HTTP/3.
    func runHTTP3() async {
        guard let quicTransport,
            let connections = try? await quicTransport.start(admission: admission)
        else {
            return
        }
        altSvc.withLock { $0 = "h3=\":\(quicTransport.boundPort)\"" }
        await withDiscardingTaskGroup { group in
            for await connection in connections {
                // Charged through the same process-wide gate as a TCP connection, and released when
                // the serve loop ends (audit addendum P0.5).
                group.addTask { await self.acceptHTTP3(connection) }
            }
        }
    }

    /// Drives the HTTP/3 engine over one QUIC connection (RFC 9114).
    ///
    /// Opens the server's control + QPACK unidirectional streams concurrently (so a slow stream open
    /// never stalls request serving), then serves each inbound stream until the connection closes.
    func serveHTTP3(_ quic: any QUICConnection) async {
        // The per-connection dispatcher (audit addendum P0.3): the registry routes engine output by
        // stream id and holds the per-stream mailbox the routed events wait in. Its byte budget is the
        // connection's own buffered-body ceiling, which is what already bounds a single engine hand-off
        // — so the mailbox bounds *accumulation* on top of it rather than restating it (audit REG-1).
        // It is built FIRST because it is also where each stream's ``DispatchPlan`` is filed, and the
        // resolver below closes over it.
        let registry = HTTP3StreamRegistry(mailboxByteBudget: limits.maxBodySize)
        // Resolve the matched route from each request head, before its DATA is buffered (Phase 1.2 /
        // 1.4), and file the resulting plan against the stream that will dispatch it. `snapshot` is
        // read per head, not per connection: an h3 connection outlives many reloads, so pinning it here
        // would make a long-lived connection permanently blind to `reloadResponder`.
        let resolveRoute: @Sendable (QUICStreamID, HTTPRequest) -> RequestBodyPolicy = {
            [self] id, request in
            let snapshot = currentSnapshot
            let plan = DispatchPlan(
                snapshot: snapshot,
                match: snapshot.resolver?
                    .match(method: request.method, path: request.path, isUpgrade: false)
            )
            registry.file(plan, for: id)
            return RequestBodyPolicy(limit: plan.bodyLimit, isStreaming: plan.streamsBody)
        }
        let engine = Engine(
            limits: limits,
            // Advertise Extended CONNECT (RFC 9220) only when the responder declares a WebSocket route.
            enableConnectProtocol: currentSnapshot.hasWebSocketRoutes,
            resolveRoute: resolveRoute
        )
        let initialActions = await engine.pendingActions()
        let serverStreams = Task {
            await self.holdServerStreams(from: initialActions, engine: engine, on: quic)
        }
        defer { serverStreams.cancel() }
        // The dispatcher's ticket channel: stream ids only, one outstanding per stream, so it needs no
        // drop policy (audit REG-1). The registry holds the continuation, because deciding between
        // waking a stream's own task and ticketing this dispatcher is its job, not its callers'.
        let (tickets, continuation) = AsyncStream<QUICStreamID>.makeStream()
        registry.attachDispatcher(continuation)
        // Visible to the drain for its whole life: GOAWAY on shutdown, forced close past the deadline
        // (audit addendum P0.5).
        // ONE read-deadline watchdog for all of this connection's request streams (P0.5) — the same
        // one-task-per-connection shape the HTTP/1.1 idle watchdog uses, not one task per stream.
        let deadlines = HTTP3StreamDeadlines<C.Instant>()
        // One value carrying every place this connection holds per-stream state, so retiring a stream
        // reaches all four of them or none (R5-P0c).
        let scope = HTTP3ConnectionScope(
            quic: quic,
            registry: registry,
            engine: engine,
            deadlines: deadlines
        )
        let watchdog = Task { await self.runHTTP3DeadlineWatchdog(in: scope) }
        defer { watchdog.cancel() }
        let handle = registerHTTP3(scope)
        defer { unregisterHTTP3(handle) }
        await withDiscardingTaskGroup { group in
            group.addTask { await self.drainRoutedHTTP3(tickets, in: scope) }
            group.addTask {
                await withDiscardingTaskGroup { streams in
                    for await stream in quic.inboundStreams() {
                        registry.register(stream)
                        // RFC 9000 §2.1 classifies the stream from its id, and RFC 9114 §6 gives the
                        // two classes different lifetimes: a request stream is bounded by read
                        // deadlines and retired when it ends, a peer unidirectional stream is
                        // long-lived and its closure is a connection error (§6.2.1). They get
                        // different loops so neither discipline can be applied to the other.
                        streams.addTask {
                            guard stream.id.isBidirectional else {
                                return await self.serveHTTP3PeerUniStream(stream, in: scope)
                            }
                            await self.serveHTTP3Stream(stream, in: scope)
                        }
                    }
                }
                // Every stream task has ended, so nothing can route any more: end the channel and let
                // the dispatcher finish its in-flight streams.
                continuation.finish()
            }
        }
    }

    /// Opens the server's unidirectional streams (writing each §6.2 preamble — the type byte, plus
    /// SETTINGS on the control stream) and holds them open until this connection's serving is cancelled.
    private func holdServerStreams(
        from actions: [HTTP3Connection.Action], engine: Engine, on quic: any QUICConnection
    ) async {
        var streams: [any QUICStream] = []
        for action in actions {
            guard case .openUniStream(let role, let preamble) = action,
                let stream = try? await quic.openStream(direction: .unidirectional)
            else { continue }
            try? await stream.send(preamble, fin: false)
            await engine.attachRoleStream(role, stream)  // so QPACK decoder-stream sends reach it
            streams.append(stream)
        }
        // Hold the control/QPACK streams open until this connection's serving is cancelled — a single
        // suspension resumed only by cancellation, with ZERO periodic wakeups (FIX #8, replacing a 1 Hz
        // keep-alive poll that existed solely to retain these stream refs). Same lifetime, no per-second
        // task wakeup per HTTP/3 connection.
        await holdUntilCancelled()
        _ = streams
    }

    /// Serves one inbound stream: feed bytes → events → respond / drive a tunnel → flush, until FIN.
    ///
    /// A request stream yields a `.request` (answered by the responder) or, with a WebSocket handler and
    /// ENABLE_CONNECT_PROTOCOL advertised, an `.extendedConnect` opening a WebSocket-over-HTTP/3 tunnel
    /// (RFC 9220) that is then driven over this stream until it closes.
    private func serveHTTP3Stream(
        _ stream: any QUICStream,
        in scope: HTTP3ConnectionScope
    ) async {
        // Everything below runs inside the retirement scope, so there is no `return` out of this
        // driver that skips the sweep — the body has to name how it ended (R5-P0c).
        await withHTTP3RequestStream(stream.id, in: scope) {
            await self.driveHTTP3Stream(stream, in: scope)
        }
    }

    /// The body of one request stream's serve loop, which must report how the stream ended.
    private func driveHTTP3Stream(
        _ stream: any QUICStream,
        in scope: HTTP3ConnectionScope
    ) async -> HTTP3StreamExit {
        let registry = scope.registry
        let deadlines = scope.deadlines
        var webSocket: WebSocketConnection?
        // The route handler resolved at this stream's Extended CONNECT (RFC 9220); tunnel DATA carries
        // only a stream id, so the handler is held here for the stream's lifetime rather than re-resolved.
        var tunnelHandler: (any WebSocketHandler)?
        // A stream that opens and then stalls is bounded from its first read on (P0.5): the header
        // budget until something decodes, the idle budget between frames after that.
        var phase = HTTP3StreamPhase.header
        // This loop waits on BOTH of the stream's work sources at once (audit REG-2): a reader task
        // owns `stream.receive()` and feeds the inbox one chunk at a time, and the dispatcher signals
        // the same inbox when a QPACK unblock (RFC 9204 §2.1.2) files routed events in our mailbox.
        // Awaiting `receive()` alone parked an unblocked `fin:false` stream until its read deadline.
        let inbox = HTTP3StreamInbox()
        let reader = Task { await Self.pumpHTTP3Inbound(stream, into: inbox) }
        defer {
            reader.cancel()
            inbox.close()
        }
        registry.attach(inbox, to: stream.id)
        armHTTP3(stream.id, phase: phase, in: scope)
        // Whether the loop left because the stream *completed* rather than because it died under us:
        // the peer's FIN, or a tunnel this server closed. Anything else is an abandonment.
        var completed = false
        reads: while true {
            let own: [HTTP3Connection.Event]
            var fin = false
            switch await inbox.next() {
                case .ended:
                    break reads
                case .routed:
                    // Woken by a deposit, not by the wire: everything owed to us is in the mailbox.
                    own = registry.takeMailbox(stream.id)
                case .inbound(let bytes, let chunkFin):
                    fin = chunkFin
                    // The read landed; handler time is not charged to a read deadline.
                    deadlines.disarm(stream.id)
                    // Engine output is addressed by stream id, not by which stream's bytes provoked it:
                    // every foreign-id event is filed against its own stream inside the engine's
                    // isolation, and only ours comes back (P0.3 / R5-P0b). The mailbox carries the ones
                    // another task routed *to* us.
                    let produced = await receiveHTTP3(stream.id, bytes, fin: chunkFin, in: scope)
                    own = registry.takeMailbox(stream.id) + produced
            }
            let handedOff = await applyHTTP3StreamEvents(
                own,
                stream: stream,
                inbox: inbox,
                in: scope,
                webSocket: &webSocket,
                tunnelHandler: &tunnelHandler
            )
            if let handedOff {
                // A streaming route or a claimed request took the stream over and concluded it; its
                // ending is this driver's ending.
                if let handler = tunnelHandler {
                    await handler.onClose()
                }
                return handedOff
            }
            if fin || webSocket?.isClosing == true {
                completed = true
                break
            }
            // Anything decoded means the head is behind us: the next read is body/tunnel progress.
            if !own.isEmpty { phase = .body }
            armHTTP3(stream.id, phase: phase, in: scope)
        }
        // Lifecycle hook: the stream ended (FIN / EOF / reset) with the tunnel still open — every
        // ending funnels through exactly one `onClose` (the in-loop paths clear `tunnelHandler`).
        if let handler = tunnelHandler {
            await handler.onClose()
        }
        // A loop that ran to a FIN answered its request; one that ended on EOF, a receive fault or a
        // reset did not, and the phase says whether the head had already reached the responder — which
        // is the difference between "may be safely retried" and "was being processed" (§8.1).
        guard completed else {
            return .abandoned(errorCode: phase.errorCode)
        }
        return .answered
    }

    /// Answers a buffered request exactly once, on the stream its id names.
    ///
    /// The claim latch is what makes "exactly once" hold across the two paths that can see the same
    /// request: this stream's own task and the connection dispatcher (audit addendum P0.3).
    func answerHTTP3Request(
        _ id: QUICStreamID,
        request: HTTPRequest,
        body: [UInt8],
        stream: any QUICStream,
        in scope: HTTP3ConnectionScope
    ) async {
        guard scope.registry.claim(id) != nil else {
            return
        }
        await respondHTTP3(id, request: request, body: body, stream: stream, in: scope)
        scope.registry.retire(id)
    }

    /// Answers a non-tunnel request — natively streamed (P6b) when the response carries a body stream,
    /// else buffered (RFC 9114 §4.1).
    private func respondHTTP3(
        _ id: QUICStreamID,
        request inbound: HTTPRequest,
        body: [UInt8],
        stream: any QUICStream,
        in scope: HTTP3ConnectionScope
    ) async {
        // The plan this stream's HEADERS resolved (CR-F12 / CR-F19): the generation whose body limit
        // was already enforced against these octets, and the route match it made.
        let plan = scope.registry.plan(for: id) ?? DispatchPlan(snapshot: currentSnapshot)
        // Build the per-request context from the QUIC connection's verified metadata (peer, TLS subject);
        // the verified mutual-TLS subject reaches handlers via `context.connection.tlsPeerSubject` rather
        // than a spoofable header (audit P0-1) — the same model the h1/h2 paths use. The same seam
        // strips every client-supplied server-asserted field off the request (audit CR-F13).
        let (request, context) = RequestContext.ingress(
            inbound, over: scope.quic, matching: plan.match
        )
        // Seam 5 of 6 (audit CR-F7). Verified against the HTTP/3 dispatcher rather than assumed:
        // engine state is behind an actor and each response is written to its own QUIC stream
        // (RFC 9000 §2 — streams are independent), so no cross-stream wire order depends on this
        // task's executor. The `sendHTTP3Response` below runs after the scoped preference is
        // restored, i.e. back on the connection's reactor, exactly as before.
        let response = await respond(
            to: request,
            body: requestBody(body, following: plan),
            context: context,
            following: plan
        )
        await sendHTTP3Response(
            response,
            omitBody: request.method == .head,
            id: id,
            stream: stream,
            in: scope
        )
    }

    /// Sends `response` on the request stream `id` — natively streamed (P6b / RFC 9114 §4.1) when it
    /// carries a body stream, else buffered.
    ///
    /// Shared by the buffered and streaming-request response paths.
    func sendHTTP3Response(
        _ response: ServerResponse,
        omitBody: Bool,
        id: QUICStreamID,
        stream: any QUICStream,
        in scope: HTTP3ConnectionScope
    ) async {
        guard let bodyStream = response.stream else {
            let actions = await scope.engine.respond(to: id, response.head, body: response.body)
            await applyHTTP3(actions, in: scope)
            return
        }
        // Native HTTP/3 streaming (P6b): pump the producer straight to the QUIC stream.
        await streamHTTP3Response(
            response.head,
            body: bodyStream,
            omitBody: omitBody,
            id: id,
            on: stream,
            in: scope
        )
    }

    /// Adds the `Alt-Svc` HTTP/3 advertisement (RFC 7838) to an h1/h2 response, when a QUIC listener
    /// is running, so clients can discover and upgrade to HTTP/3 on the same authority.
    func withAltSvc(_ response: HTTPResponse) -> HTTPResponse {
        guard let value = altSvc.withLock(\.self) else {
            return response
        }
        var advertised = response
        // Use the registered constant (no per-response token re-validation / canonicalName build).
        advertised.headerFields.append(value, for: .altSvc)
        return advertised
    }
}
