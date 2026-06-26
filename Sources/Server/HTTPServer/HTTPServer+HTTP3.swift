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

extension HTTPServer {
    /// Serializes the non-`Sendable` ``HTTP3Connection`` engine across a connection's concurrent streams.
    private actor Engine {
        private var connection: HTTP3Connection
        /// The server's own unidirectional streams by role (control / QPACK encoder+decoder), so
        /// role-addressed engine sends — QPACK Insert Count Increment / Section Acknowledgment on the
        /// decoder stream (RFC 9204 §4.4) — reach the right stream.
        private var roleStreams: [HTTP3StreamRole: any QUICStream] = [:]

        init(limits: HTTPLimits) {
            connection = HTTP3Connection(localSettings: HTTP3Settings(), limits: limits)
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
        let engine = Engine(limits: limits)
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

    /// Serves one inbound stream: feed bytes → events → respond → flush, until FIN.
    private func serveHTTP3Stream(
        _ stream: any QUICStream, engine: Engine, quic: any QUICConnection
    ) async {
        while let chunk = try? await stream.receive() {
            let (events, actions) = await engine.receive(stream.id, chunk.bytes, fin: chunk.fin)
            await applyHTTP3(actions, stream: stream, engine: engine, quic: quic)
            for case .request(let id, let request, let body) in events {
                let current = currentResponder  // hot-swappable responder, read once (G4a)
                let response = await current.respond(to: request, body: body)
                if let bodyStream = response.stream {
                    // Native HTTP/3 streaming (P6b): pump the producer straight to the QUIC stream.
                    await streamHTTP3Response(
                        response.head,
                        body: bodyStream,
                        omitBody: request.method == .head,
                        id: id,
                        engine: engine,
                        on: stream
                    )
                }
                else {
                    let responseActions = await engine.respond(
                        to: id, response.head, body: response.body
                    )
                    await applyHTTP3(responseActions, stream: stream, engine: engine, quic: quic)
                }
            }
            if chunk.fin { break }
        }
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
