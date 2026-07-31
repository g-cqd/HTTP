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

        /// Feeds one stream's bytes (a connection error is swallowed; its CONNECTION_CLOSE is queued).
        func receive(
            _ id: QUICStreamID, _ bytes: [UInt8], fin: Bool
        ) -> (events: [HTTP3Connection.Event], actions: [HTTP3Connection.Action]) {
            let events = (try? connection.receive(id, bytes, fin: fin)) ?? []
            return (events, connection.outbound())
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

        /// Whether `id` still holds a QPACK-blocked field section (RFC 9204 §2.1.2) — its request has
        /// not surfaced and will do so from another stream's receive (audit addendum P0.3).
        func isBlocked(_ id: QUICStreamID) -> Bool {
            connection.isBlocked(id)
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
        // stream id, and `routed` carries the events a stream task produced for a *different* stream.
        // Bounded — the engine only crosses streams when it unblocks a QPACK-blocked section, and it
        // caps those at `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204 §2.1.2), well under this budget.
        // It is built FIRST because it is also where each stream's ``DispatchPlan`` is filed, and the
        // resolver below closes over it.
        let registry = HTTP3StreamRegistry()
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
        let (routed, continuation) = AsyncStream<HTTP3RoutedEvents>
            .makeStream(
                bufferingPolicy: .bufferingOldest(Self.http3RoutedEventBudget)
            )
        // Visible to the drain for its whole life: GOAWAY on shutdown, forced close past the deadline
        // (audit addendum P0.5).
        // ONE read-deadline watchdog for all of this connection's request streams (P0.5) — the same
        // one-task-per-connection shape the HTTP/1.1 idle watchdog uses, not one task per stream.
        let deadlines = HTTP3StreamDeadlines<C.Instant>()
        let watchdog = Task {
            await self.runHTTP3DeadlineWatchdog(deadlines: deadlines, registry: registry)
        }
        defer { watchdog.cancel() }
        let handle = registerHTTP3(
            HTTP3Handle(quic: quic, registry: registry, engine: engine)
        )
        defer { unregisterHTTP3(handle) }
        await withDiscardingTaskGroup { group in
            group.addTask {
                await self.drainRoutedHTTP3(
                    routed,
                    registry: registry,
                    engine: engine,
                    quic: quic,
                    deadlines: deadlines
                )
            }
            group.addTask {
                await withDiscardingTaskGroup { streams in
                    for await stream in quic.inboundStreams() {
                        registry.register(stream)
                        streams.addTask {
                            await self.serveHTTP3Stream(
                                stream,
                                engine: engine,
                                quic: quic,
                                registry: registry,
                                routed: continuation,
                                deadlines: deadlines
                            )
                        }
                    }
                }
                // Every stream task has ended, so nothing can route any more: end the channel and let
                // the dispatcher finish its in-flight batches.
                continuation.finish()
            }
        }
    }

    /// The most routed event batches a connection may hold before the oldest are dropped.
    ///
    /// Sized well above the engine's blocked-stream cap (RFC 9204 §2.1.2) so a conforming peer never
    /// reaches it; it is a CWE-770 bound, not a working limit.
    static var http3RoutedEventBudget: Int { 256 }

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
        engine: Engine,
        quic: any QUICConnection,
        registry: HTTP3StreamRegistry,
        routed: AsyncStream<HTTP3RoutedEvents>.Continuation,
        deadlines: HTTP3StreamDeadlines<C.Instant>
    ) async {
        var webSocket: WebSocketConnection?
        // The route handler resolved at this stream's Extended CONNECT (RFC 9220); tunnel DATA carries
        // only a stream id, so the handler is held here for the stream's lifetime rather than re-resolved.
        var tunnelHandler: (any WebSocketHandler)?
        // A stream that opens and then stalls is bounded from its first read on (P0.5): the header
        // budget until something decodes, the idle budget between frames after that.
        var phase = HTTP3StreamPhase.header
        armHTTP3(stream.id, phase: phase, on: deadlines)
        defer { deadlines.disarm(stream.id) }
        while let chunk = try? await stream.receive() {
            deadlines.disarm(stream.id)  // the read landed; handler time is not a read deadline
            let (produced, actions) = await engine.receive(stream.id, chunk.bytes, fin: chunk.fin)
            await applyHTTP3(actions, registry: registry, engine: engine, quic: quic)
            // Engine output is addressed by stream id, not by which stream's bytes provoked it: hand
            // every foreign-id event to the connection dispatcher and keep only our own (P0.3). The
            // mailbox carries back the ones another task routed *to* us while we were parked.
            let own =
                registry.takeMailbox(stream.id)
                + partitionHTTP3Events(produced, owner: stream.id, routed: routed)
            for (index, event) in own.enumerated() {
                switch event {
                    case .request(let id, let request, let body):
                        await answerHTTP3Request(
                            id,
                            request: request,
                            body: body,
                            stream: stream,
                            engine: engine,
                            quic: quic,
                            registry: registry
                        )
                    case .requestHead(let id, let request):
                        // A streaming route (Phase 1.4) takes over this stream for its lifetime: feed the
                        // body off the wire into the handler's stream, then send its response.
                        guard registry.claim(id) != nil else {
                            return
                        }
                        await serveHTTP3StreamingRequest(
                            id,
                            request: request,
                            buffered: Self.trailingBody(of: own, after: index),
                            stream: stream,
                            engine: engine,
                            quic: quic,
                            registry: registry,
                            deadlines: deadlines
                        )
                        return
                    case .requestBodyChunk, .requestEnd:
                        break  // consumed by serveHTTP3StreamingRequest — never standalone here
                    case .extendedConnect, .tunnelData, .tunnelClosed:
                        await handleHTTP3TunnelEvent(
                            event,
                            stream: stream,
                            engine: engine,
                            webSocket: &webSocket,
                            tunnelHandler: &tunnelHandler
                        )
                    case .goAway:
                        break
                }
            }
            if chunk.fin || webSocket?.isClosing == true {
                break
            }
            // Anything decoded means the head is behind us: the next read is body/tunnel progress.
            if !own.isEmpty { phase = .body }
            armHTTP3(stream.id, phase: phase, on: deadlines)
        }
        // Lifecycle hook: the stream ended (FIN / EOF / reset) with the tunnel still open — every
        // ending funnels through exactly one `onClose` (the in-loop paths clear `tunnelHandler`).
        if let handler = tunnelHandler {
            await handler.onClose()
        }
        // Keep the writer reachable only while the engine still owes this stream a request: a blocked
        // field section surfaces later, from the encoder stream's receive (RFC 9204 §2.1.2), and the
        // dispatcher must still be able to answer on it.
        registry.endDriving(stream.id, retain: await engine.isBlocked(stream.id))
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
        engine: Engine,
        quic: any QUICConnection,
        registry: HTTP3StreamRegistry
    ) async {
        guard registry.claim(id) != nil else {
            return
        }
        await respondHTTP3(
            id,
            request: request,
            body: body,
            stream: stream,
            engine: engine,
            quic: quic,
            registry: registry
        )
        registry.retire(id)
    }

    /// Answers a non-tunnel request — natively streamed (P6b) when the response carries a body stream,
    /// else buffered (RFC 9114 §4.1).
    private func respondHTTP3(
        _ id: QUICStreamID,
        request inbound: HTTPRequest,
        body: [UInt8],
        stream: any QUICStream,
        engine: Engine,
        quic: any QUICConnection,
        registry: HTTP3StreamRegistry
    ) async {
        // The plan this stream's HEADERS resolved (CR-F12 / CR-F19): the generation whose body limit
        // was already enforced against these octets, and the route match it made.
        let plan = registry.plan(for: id) ?? DispatchPlan(snapshot: currentSnapshot)
        // Build the per-request context from the QUIC connection's verified metadata (peer, TLS subject);
        // the verified mutual-TLS subject reaches handlers via `context.connection.tlsPeerSubject` rather
        // than a spoofable header (audit P0-1) — the same model the h1/h2 paths use. The same seam
        // strips every client-supplied server-asserted field off the request (audit CR-F13).
        let (request, context) = RequestContext.ingress(
            inbound, over: quic, matching: plan.match
        )
        let response = await plan.snapshot.responder.respond(
            to: request, body: requestBody(body, following: plan), context: context
        )
        await sendHTTP3Response(
            response,
            omitBody: request.method == .head,
            id: id,
            stream: stream,
            engine: engine,
            quic: quic,
            registry: registry
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
        engine: Engine,
        quic: any QUICConnection,
        registry: HTTP3StreamRegistry
    ) async {
        if let bodyStream = response.stream {
            // Native HTTP/3 streaming (P6b): pump the producer straight to the QUIC stream.
            await streamHTTP3Response(
                response.head,
                body: bodyStream,
                omitBody: omitBody,
                id: id,
                engine: engine,
                on: stream
            )
        }
        else {
            let responseActions = await engine.respond(to: id, response.head, body: response.body)
            await applyHTTP3(responseActions, registry: registry, engine: engine, quic: quic)
        }
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
