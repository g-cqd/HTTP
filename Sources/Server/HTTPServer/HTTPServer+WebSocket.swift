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
        // The frame cap rides the message cap: a single frame can never legitimately exceed the
        // message it belongs to, so a smaller standalone frame default would spuriously reject
        // cap-legal unfragmented messages (RFC 6455 §5.4 — Autobahn 9.1/9.2 send up to 16 MiB in
        // one frame).
        var engine = WebSocketConnection(
            maxFrameSize: limits.effectiveWebSocketMessageSize,
            maxMessageSize: limits.effectiveWebSocketMessageSize,
            permessageDeflate: permessageDeflate
        )
        let (wakeups, continuation) = AsyncStream.makeStream(
            of: WebSocketWakeup.self, bufferingPolicy: .bufferingNewest(256)
        )
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
        // Lifecycle hook: the session is over — every ending funnels through here exactly once
        // (clean Close handshake, abrupt EOF, idle timeout, send failure).
        await handler.onClose()
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
        engine: inout HTTP2Connection,
        group: inout DiscardingTaskGroup,
        webSockets: inout [HTTP2StreamID: HTTP2WebSocketTunnel],
        pendingTunnels: inout Int,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) {
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
                let (signals, mailbox) = AsyncStream.makeStream(
                    of: HTTP2TunnelSignal.self, bufferingPolicy: .unbounded
                )
                webSockets[streamID] = HTTP2WebSocketTunnel(mailbox: mailbox)
                pendingTunnels += 1
                group.addTask { [self] in
                    await runHTTP2Tunnel(
                        streamID: streamID,
                        handler: handler,
                        permessageDeflate: permessageDeflate,
                        signals: signals,
                        into: continuation
                    )
                }
            case .tunnelData(let streamID, let bytes):
                webSockets[streamID]?.mailbox.yield(.bytes(bytes))
            case .tunnelClosed(let streamID), .streamReset(let streamID, _):
                // Exactly-once: only a tunnel still tracked gets the peer-ended signal (a self-closed
                // removal — see `.tunnelEnded` in HTTPServer+HTTP2.swift — has already removed it). The
                // pump task still reports back via `.tunnelEnded` once it processes this signal, so
                // `pendingTunnels` (not this map) is what the EOF drain check waits on.
                if let tunnel = webSockets.removeValue(forKey: streamID) {
                    tunnel.mailbox.yield(.peerEnded)
                    tunnel.mailbox.finish()
                }
            default:
                break
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
    /// decided to close, the peer ended the tunnel (`.peerEnded`), or the connection is tearing down
    /// (cancellation unblocks the `for await` below exactly like a normal completion — `AsyncStream`
    /// iteration is cancellation-aware on this runtime). `.tunnelEnded` is likewise yielded UNCONDITIONALLY
    /// on every exit — including a cancelled one — so the consumer's `pendingTunnels` count (the EOF drain
    /// check) always reaches zero and the connection is never held open waiting on a pump task that has
    /// actually already finished.
    private func runHTTP2Tunnel(
        streamID: HTTP2StreamID,
        handler: any WebSocketHandler,
        permessageDeflate: PermessageDeflateParameters?,
        signals: AsyncStream<HTTP2TunnelSignal>,
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
        signalLoop: for await signal in signals {
            switch signal {
                case .bytes(let bytes):
                    // A violation leaves a queued Close and sets `isClosing`; handled below.
                    let events = (try? socket.receive(bytes)) ?? []
                    for event in events {
                        for action in await handler.handle(event) { socket.apply(action) }
                    }
                    let outbound = socket.outboundBytes()
                    if !outbound.isEmpty { continuation.yield(.tunnelOutbound(streamID, outbound)) }
                    if socket.isClosing {
                        selfClosed = true
                        break signalLoop
                    }
                case .peerEnded:
                    break signalLoop
            }
        }
        await handler.onClose()  // lifecycle hook — the session is over, exactly once
        continuation.yield(.tunnelEnded(streamID, selfClosed: selfClosed))
    }
}
