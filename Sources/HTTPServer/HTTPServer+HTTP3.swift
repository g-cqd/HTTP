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

        init(limits: HTTPLimits) {
            connection = HTTP3Connection(localSettings: HTTP3Settings(), limits: limits)
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
        let serverStreams = Task { await self.holdServerStreams(from: initialActions, on: quic) }
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
        from actions: [HTTP3Connection.Action], on quic: any QUICConnection
    ) async {
        var streams: [any QUICStream] = []
        for action in actions {
            guard case .openUniStream(_, let preamble) = action,
                let stream = try? await quic.openStream(direction: .unidirectional)
            else { continue }
            try? await stream.send(preamble, fin: false)
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
            await applyHTTP3(actions, stream: stream, quic: quic)
            for case .request(let id, let request, let body) in events {
                let response = await responder.respond(to: request, body: body)
                let responseActions = await engine.respond(
                    to: id, response.head, body: response.body
                )
                await applyHTTP3(responseActions, stream: stream, quic: quic)
            }
            if chunk.fin { break }
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

    /// Performs the engine's outbound actions for `stream` (response sends, resets, connection close).
    private func applyHTTP3(
        _ actions: [HTTP3Connection.Action], stream: any QUICStream, quic: any QUICConnection
    ) async {
        for action in actions {
            switch action {
                case .send(.id(let id), let bytes, let fin) where id == stream.id:
                    try? await stream.send(bytes, fin: fin)
                case .resetStream(let id, let code) where id == stream.id:
                    stream.reset(errorCode: code)
                case .closeConnection(let code):
                    await quic.close(errorCode: code)
                default:
                    break  // openUniStream is handled at startup; other-id sends do not occur in v1
            }
        }
    }
}
