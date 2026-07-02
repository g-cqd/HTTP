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
    /// A reader task feeds inbound bytes, and a hub (Phase 2.7) feeds broadcasts, into one
    /// ``WebSocketWakeup`` stream the pump consumes — so the server can push a frame without the pump
    /// blocking on `receive`.
    private func driveWebSocket(
        _ connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        handler: any WebSocketHandler,
        hub: WebSocketHub?,
        topic: String?,
        carryover: [UInt8],
        permessageDeflate: PermessageDeflateParameters?
    ) async {
        var engine = WebSocketConnection(
            maxMessageSize: limits.effectiveWebSocketMessageSize,
            permessageDeflate: permessageDeflate
        )
        let (wakeups, continuation) = AsyncStream.makeStream(
            of: WebSocketWakeup.self, bufferingPolicy: .bufferingNewest(256)
        )
        // Hub (Phase 2.7): register this connection's broadcast sink and auto-subscribe it to the topic,
        // so a published message arrives as a `.broadcast` wakeup, applied to the engine below.
        var token: UInt64?
        if let hub, let topic {
            token = await hub.register { message in continuation.yield(.broadcast(message)) }
            if let token { await hub.subscribe(token, to: topic) }
        }
        // Reader: feed the carryover, then inbound bytes (timed by the idle deadline), into the stream.
        let reader = Task {
            if !carryover.isEmpty { continuation.yield(.inbound(carryover)) }
            while true {
                deadline.arm(clock.now.advanced(by: limits.keepAliveTimeout))
                let chunk = try? await connection.receive(maxLength: 16_384)
                deadline.disarm()
                guard let chunk, !chunk.isEmpty else {
                    continuation.yield(.closed)  // EOF, idle timeout, or read failure
                    return
                }
                continuation.yield(.inbound(chunk))
            }
        }
        await pumpWebSocket(wakeups, engine: &engine, handler: handler, connection: connection)
        reader.cancel()
        continuation.finish()
        if let hub, let token { await hub.remove(token) }
        await connection.close()
    }

    /// Consumes the wakeup stream: receive → events → handler actions, or a hub broadcast → send; flushes
    /// after each, stopping on a queued Close, the reader closing, or a send failure (RFC 6455 §6).
    private func pumpWebSocket(
        _ wakeups: AsyncStream<WebSocketWakeup>,
        engine: inout WebSocketConnection,
        handler: any WebSocketHandler,
        connection: any TransportConnection
    ) async {
        for await wakeup in wakeups {
            var ended = false
            switch wakeup {
                case .inbound(let bytes):
                    do {
                        for event in try engine.receive(bytes) {
                            for action in await handler.handle(event) { engine.apply(action) }
                        }
                    }
                    catch {
                        ended = true  // the engine queued a Close; flush it below, then stop
                    }
                case .broadcast(.text(let string)):
                    engine.apply(.sendText(string))
                case .broadcast(.binary(let bytes)):
                    engine.apply(.sendBinary(bytes))
                case .closed:
                    ended = true
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

    // MARK: WebSocket over HTTP/2 (RFC 8441 / RFC 9220)

    /// Dispatches a tunnel event from the HTTP/2 engine for a WebSocket-over-HTTP/2 stream: accept an
    /// Extended CONNECT (RFC 8441 §4), pump tunnel DATA through that stream's WebSocket engine, and
    /// tear the stream down on close or reset.
    func handleHTTP2Tunnel(
        _ event: HTTP2Connection.Event,
        engine: inout HTTP2Connection,
        webSockets: inout [HTTP2StreamID: HTTP2WebSocketTunnel]
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
                try? engine.acceptTunnel(  // 200, no END_STREAM (RFC 8441 §5)
                    streamID,
                    secWebSocketExtensions: permessageDeflate?.headerValue
                )
                webSockets[streamID] = HTTP2WebSocketTunnel(
                    socket: WebSocketConnection(
                        maxMessageSize: limits.effectiveWebSocketMessageSize,
                        permessageDeflate: permessageDeflate
                    ),
                    handler: handler
                )
            case .tunnelData(let streamID, let bytes):
                guard var tunnel = webSockets[streamID] else {
                    return
                }
                await driveTunnel(
                    &tunnel.socket,
                    bytes: bytes,
                    streamID: streamID,
                    engine: &engine,
                    handler: tunnel.handler
                )
                if tunnel.socket.isClosing {
                    try? engine.closeTunnel(streamID)
                    webSockets[streamID] = nil
                }
                else {
                    webSockets[streamID] = tunnel
                }
            case .tunnelClosed(let streamID), .streamReset(let streamID, _):
                webSockets[streamID] = nil
            default:
                break
        }
    }

    /// Feeds tunnel `bytes` to the stream's WebSocket engine and writes the frames it produces back as
    /// tunnel DATA (RFC 8441 §5 over RFC 6455 §6); a violation leaves a queued Close to flush.
    private func driveTunnel(
        _ socket: inout WebSocketConnection,
        bytes: [UInt8],
        streamID: HTTP2StreamID,
        engine: inout HTTP2Connection,
        handler: any WebSocketHandler
    ) async {
        // A violation leaves a queued Close and sets `isClosing`; flush it below.
        let events = (try? socket.receive(bytes)) ?? []
        for event in events {
            for action in await handler.handle(event) { socket.apply(action) }
        }
        let outbound = socket.outboundBytes()
        if !outbound.isEmpty { engine.sendTunnelData(streamID, outbound) }
    }
}
