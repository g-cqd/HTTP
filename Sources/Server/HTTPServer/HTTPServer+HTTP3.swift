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
            resolveBodyLimit: @escaping @Sendable (HTTPRequest) -> Int?,
            resolveStreamsBody: @escaping @Sendable (HTTPRequest) -> Bool
        ) {
            var settings = HTTP3Settings()
            settings.enableConnectProtocol = enableConnectProtocol  // RFC 9220 — WebSocket over h3
            connection = HTTP3Connection(
                localSettings: settings,
                limits: limits,
                resolveBodyLimit: resolveBodyLimit,
                resolveStreamsBody: resolveStreamsBody
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
    }

    /// Runs the QUIC listener: advertise `Alt-Svc` (RFC 7838), then serve each connection as HTTP/3.
    func runHTTP3() async {
        guard let quicTransport, let connections = try? await quicTransport.start() else {
            return
        }
        altSvc.withLock { $0 = "h3=\":\(quicTransport.boundPort)\"" }
        await withDiscardingTaskGroup { group in
            for await connection in connections {
                group.addTask { await self.serveHTTP3(connection) }
            }
        }
    }

    /// Drives the HTTP/3 engine over one QUIC connection (RFC 9114).
    ///
    /// Opens the server's control + QPACK unidirectional streams concurrently (so a slow stream open
    /// never stalls request serving), then serves each inbound stream until the connection closes.
    func serveHTTP3(_ quic: any QUICConnection) async {
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
        let engine = Engine(
            limits: limits,
            // Advertise Extended CONNECT (RFC 9220) only when the responder declares a WebSocket route.
            enableConnectProtocol: currentResolver?.hasWebSocketRoutes ?? false,
            resolveBodyLimit: resolveBodyLimit,
            resolveStreamsBody: resolveStreamsBody
        )
        let initialActions = await engine.pendingActions()
        let serverStreams = Task {
            await self.holdServerStreams(from: initialActions, engine: engine, on: quic)
        }
        defer { serverStreams.cancel() }
        await withDiscardingTaskGroup { group in
            for await stream in quic.inboundStreams() {
                group.addTask { await self.serveHTTP3Stream(stream, engine: engine, quic: quic) }
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
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(1))  // keep the control/QPACK streams alive
        }
        _ = streams
    }

    /// Serves one inbound stream: feed bytes → events → respond / drive a tunnel → flush, until FIN.
    ///
    /// A request stream yields a `.request` (answered by the responder) or, with a WebSocket handler and
    /// ENABLE_CONNECT_PROTOCOL advertised, an `.extendedConnect` opening a WebSocket-over-HTTP/3 tunnel
    /// (RFC 9220) that is then driven over this stream until it closes.
    private func serveHTTP3Stream(
        _ stream: any QUICStream, engine: Engine, quic: any QUICConnection
    ) async {
        var webSocket: WebSocketConnection?
        // The route handler resolved at this stream's Extended CONNECT (RFC 9220); tunnel DATA carries
        // only a stream id, so the handler is held here for the stream's lifetime rather than re-resolved.
        var tunnelHandler: (any WebSocketHandler)?
        while let chunk = try? await stream.receive() {
            let (events, actions) = await engine.receive(stream.id, chunk.bytes, fin: chunk.fin)
            await applyHTTP3(actions, stream: stream, engine: engine, quic: quic)
            for (index, event) in events.enumerated() {
                switch event {
                    case .request(let id, let request, let body):
                        await respondHTTP3(
                            id,
                            request: request,
                            body: body,
                            stream: stream,
                            engine: engine,
                            quic: quic
                        )
                    case .requestHead(let id, let request):
                        // A streaming route (Phase 1.4) takes over this stream for its lifetime: feed the
                        // body off the wire into the handler's stream, then send its response.
                        await serveHTTP3StreamingRequest(
                            id,
                            request: request,
                            buffered: Self.trailingBody(of: events, after: index),
                            stream: stream,
                            engine: engine,
                            quic: quic
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
        }
        // Lifecycle hook: the stream ended (FIN / EOF / reset) with the tunnel still open — every
        // ending funnels through exactly one `onClose` (the in-loop paths clear `tunnelHandler`).
        if let handler = tunnelHandler {
            await handler.onClose()
        }
    }

    /// Answers a non-tunnel request — natively streamed (P6b) when the response carries a body stream,
    /// else buffered (RFC 9114 §4.1).
    private func respondHTTP3(
        _ id: QUICStreamID,
        request: HTTPRequest,
        body: [UInt8],
        stream: any QUICStream,
        engine: Engine,
        quic: any QUICConnection
    ) async {
        // Build the per-request context from the QUIC connection's verified metadata (peer, TLS subject);
        // the verified mutual-TLS subject reaches handlers via `context.connection.tlsPeerSubject` rather
        // than a spoofable header (audit P0-1) — the same model the h1/h2 paths use.
        let context = RequestContext(quic: quic, request: request)
        let current = currentResponder  // hot-swappable responder, read once (G4a)
        let response = await current.respond(
            to: request, body: requestBody(body, for: request), context: context
        )
        await sendHTTP3Response(
            response,
            omitBody: request.method == .head,
            id: id,
            stream: stream,
            engine: engine,
            quic: quic
        )
    }

    /// Sends `response` on the request stream `id` — natively streamed (P6b / RFC 9114 §4.1) when it
    /// carries a body stream, else buffered.
    ///
    /// Shared by the buffered and streaming-request response paths.
    private func sendHTTP3Response(
        _ response: ServerResponse,
        omitBody: Bool,
        id: QUICStreamID,
        stream: any QUICStream,
        engine: Engine,
        quic: any QUICConnection
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
            await applyHTTP3(responseActions, stream: stream, engine: engine, quic: quic)
        }
    }

    /// Drives a streaming-route request on its QUIC stream (Phase 1.4): feed the body off the wire into a
    /// back-pressured handoff the handler consumes, then send the handler's response on the same stream.
    ///
    /// The handler runs in a child task and consumes the body via the stream; the feed loop suspends on a
    /// full handoff slot until the handler takes each chunk (1-chunk backpressure), and QUIC's per-stream
    /// flow control back-pressures the sender in turn — bounded memory for an arbitrarily large upload.
    /// The handler abandons the handoff on return, so the feed loop resumes (dropping the rest) even if
    /// the handler did not drain the body; the whole body is still read off the wire to FIN.
    private func serveHTTP3StreamingRequest(
        _ id: QUICStreamID,
        request: HTTPRequest,
        buffered: (chunks: [[UInt8]], ended: Bool),
        stream: any QUICStream,
        engine: Engine,
        quic: any QUICConnection
    ) async {
        let handoff = AsyncHandoff()
        let context = RequestContext(quic: quic, request: request)
        let current = currentResponder  // hot-swappable responder, read once (G4a)
        let handler = Task {
            let response = await current.respond(
                to: request,
                body: .stream(HTTPRequestBodyStream(handoff: handoff)),
                context: context
            )
            await handoff.abandon()  // unblock the feeder if the handler returned without draining
            return response
        }
        var ended = buffered.ended
        for chunk in buffered.chunks {
            await handoff.offer(chunk)
        }
        while !ended, let chunk = try? await stream.receive() {
            let (events, actions) = await engine.receive(id, chunk.bytes, fin: chunk.fin)
            await applyHTTP3(actions, stream: stream, engine: engine, quic: quic)
            for event in events {
                if case .requestBodyChunk(_, let bytes) = event {
                    await handoff.offer(bytes)
                }
                else if case .requestEnd = event {
                    ended = true
                }
            }
            if chunk.fin {
                break
            }
        }
        await handoff.finish()
        let response = await handler.value
        await sendHTTP3Response(
            response,
            omitBody: request.method == .head,
            id: id,
            stream: stream,
            engine: engine,
            quic: quic
        )
    }

    /// Collects the body chunks (and whether `requestEnd` arrived) that follow a `requestHead` in the
    /// same event batch — handed to ``serveHTTP3StreamingRequest`` so a HEADERS+DATA+FIN that decoded
    /// together is not lost before the feed loop starts.
    private static func trailingBody(
        of events: [HTTP3Connection.Event], after index: Int
    ) -> (chunks: [[UInt8]], ended: Bool) {
        var chunks: [[UInt8]] = []
        var ended = false
        for event in events[(index + 1)...] {
            if case .requestBodyChunk(_, let bytes) = event {
                chunks.append(bytes)
            }
            else if case .requestEnd = event {
                ended = true
            }
        }
        return (chunks, ended)
    }

    /// Streams a response natively on a QUIC request stream (RFC 9114 §4.1).
    ///
    /// The QPACK HEADERS frame goes first (`fin:false`), then each body chunk as a DATA frame as the
    /// producer yields it, then an empty FIN ends the stream; a HEAD request sends the headers with FIN
    /// and no body (RFC 9110 §9.3.2). QUIC streams are independent with transport-level backpressure
    /// (`stream.send` suspends until the transport accepts the bytes), so — unlike HTTP/2's shared,
    /// window-coupled connection — the producer drives the stream inline with no flow-control deadlock.
    /// A producer or transport fault mid-body resets the stream with H3_REQUEST_INCOMPLETE (§8.1) so the
    /// client sees a truncated response rather than a silently short one.
    private func streamHTTP3Response(
        _ head: HTTPResponse,
        body: ResponseStream,
        omitBody: Bool,
        id: QUICStreamID,
        engine: Engine,
        on stream: any QUICStream
    ) async {
        guard let headerBytes = await engine.respondHeaders(to: id, head) else {
            stream.reset(errorCode: HTTP3ErrorCode.h3InternalError.rawValue)
            return
        }
        do {
            guard !omitBody else {
                // HEAD: the header section with FIN and no body (RFC 9110 §9.3.2).
                try await stream.send(headerBytes, fin: true)
                return
            }
            try await stream.send(headerBytes, fin: false)
            try await body.produce(H3StreamWriter(stream: stream))
            try await stream.send([], fin: true)  // end-of-body (RFC 9114 §4.1)
        }
        catch {
            stream.reset(errorCode: HTTP3ErrorCode.h3RequestIncomplete.rawValue)
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

    /// Writes HTTP/3 response-body chunks as DATA frames (RFC 9114 §7.2.1), one `send` per chunk so the
    /// QUIC stream's flow control is the backpressure point — no engine round-trip, since the body of an
    /// independent QUIC stream needs no connection state (RFC 9000 §2).
    private struct H3StreamWriter: ResponseBodyWriter {
        let stream: any QUICStream

        func write(_ chunk: [UInt8]) async throws {
            guard !chunk.isEmpty else {
                return
            }
            try await stream.send(HTTP3Connection.dataFrame(chunk), fin: false)
        }
    }

    /// Performs the engine's outbound actions for `stream` (response sends, resets, connection close).
    private func applyHTTP3(
        _ actions: [HTTP3Connection.Action],
        stream: any QUICStream,
        engine: Engine,
        quic: any QUICConnection
    ) async {
        for action in actions {
            switch action {
                case .send(.id(let id), let bytes, let fin) where id == stream.id:
                    try? await stream.send(bytes, fin: fin)
                case .send(.role(let role), let bytes, let fin):
                    // QPACK Insert Count Increment / Section Acknowledgment on our decoder stream (§4.4).
                    await engine.sendOnRole(role, bytes, fin: fin)
                case .resetStream(let id, let code) where id == stream.id:
                    stream.reset(errorCode: code)
                case .closeConnection(let code):
                    await quic.close(errorCode: code)
                default:
                    break  // openUniStream is handled at startup; other-id sends do not occur here
            }
        }
    }
}
