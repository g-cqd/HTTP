//
//  HTTPServer+HTTP3Tunnel.swift
//  HTTPServer
//
//  WebSocket-over-HTTP/3 tunnel handling (RFC 9220 over RFC 8441 semantics), split out of
//  HTTPServer+HTTP3.swift so the stream-serving file stays focused: accept an Extended CONNECT
//  (with the same CSWSH origin defense and permessage-deflate negotiation as h1/h2), pump tunnel
//  DATA through the stream's WebSocket engine, and drive the handler lifecycle hooks
//  (onOpen speaks first; onClose fires exactly once however the tunnel ends).
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport
internal import WebSocket

extension HTTPServer {
    /// Dispatches one tunnel event for a WebSocket-over-HTTP/3 stream (RFC 9220): accept the
    /// Extended CONNECT (firing ``WebSocketHandler/onOpen()`` — the handler speaks first), pump
    /// tunnel DATA, and fire ``WebSocketHandler/onClose()`` exactly once when the tunnel ends
    /// (the caller's stream-end path covers a stream that dies with the tunnel still open).
    func handleHTTP3TunnelEvent(
        _ event: HTTP3Connection.Event,
        stream: any QUICStream,
        in scope: HTTP3ConnectionScope,
        webSocket: inout WebSocketConnection?,
        tunnelHandler: inout (any WebSocketHandler)?
    ) async {
        let engine = scope.engine
        switch event {
            case .extendedConnect(let id, let request, let proto):
                let tunnel = await acceptHTTP3Tunnel(
                    id, request: request, protocol: proto, on: stream, in: scope
                )
                webSocket = tunnel?.socket
                tunnelHandler = tunnel?.handler
                // Lifecycle hook: the tunnel is open — let the handler speak first.
                if var socket = webSocket, let handler = tunnelHandler {
                    for action in await handler.onOpen() { socket.apply(action) }
                    let greeting = socket.outboundBytes()
                    if !greeting.isEmpty {
                        let frame = await engine.sendTunnelData(id, greeting)
                        try? await stream.send(frame, fin: false)
                    }
                    webSocket = socket
                }
            case .tunnelData(_, let bytes):
                webSocket = await pumpHTTP3Tunnel(
                    webSocket,
                    handler: tunnelHandler,
                    bytes: bytes,
                    on: stream,
                    engine: engine
                )
                // The pump FINned a closing tunnel — fire the close hook exactly once.
                if webSocket == nil, let handler = tunnelHandler {
                    tunnelHandler = nil
                    await handler.onClose()
                }
            case .tunnelClosed:
                webSocket = nil
                if let handler = tunnelHandler {
                    tunnelHandler = nil
                    await handler.onClose()  // lifecycle hook — the peer ended the tunnel
                }
            default:
                break  // not a tunnel event (the caller routes only the three cases here)
        }
    }

    /// Accepts (or refuses) a WebSocket-over-HTTP/3 Extended CONNECT (RFC 9220) — the same CSWSH origin
    /// defense and permessage-deflate negotiation as the HTTP/2 tunnel.
    ///
    /// On success it sends the engine's `200` (no FIN) and returns the per-stream ``WebSocketConnection``
    /// paired with the route's handler; a path with no WebSocket route, a disallowed origin, a declined
    /// upgrade, or a framing error resets the stream and returns nil.
    ///
    /// The handler is resolved from the ``DispatchPlan`` this stream's HEADERS filed in the registry,
    /// never from the live snapshot (audit R5-SEC1b) — the h3 half of the same fix the HTTP/2 tunnel
    /// takes in ``resolveHTTP2Tunnel(_:protocol:following:)``. An h3 connection outlives many
    /// ``reloadResponder(_:)`` calls, and the head and the accept are separated by actor hops, so
    /// rereading the mutex here let a reload hand the upgrade a different generation than the one whose
    /// table admitted the request (2026-07-31 audit, finding 12).
    ///
    /// The plan's own ``DispatchPlan/match`` is not reused: `serveHTTP3`'s `resolveRoute` matches every
    /// head with `isUpgrade: false`, so it never carries the WebSocket route. The *snapshot* is what
    /// carries over, and the table is walked again against that generation's resolver.
    private func acceptHTTP3Tunnel(
        _ id: QUICStreamID,
        request: HTTPRequest,
        protocol proto: String,
        on stream: any QUICStream,
        in scope: HTTP3ConnectionScope
    ) async -> (socket: WebSocketConnection, handler: any WebSocketHandler)? {
        // Refused rather than re-resolved against `currentSnapshot`: a silent fallback IS the bug
        // (R5-SEC1b). The engine calls `resolveRoute` when the field section decodes, before it emits
        // `.extendedConnect` (HTTP3Connection+Request.swift), so a plan is filed on every real path and
        // this is a fail-closed answer to an impossible state. H3_INTERNAL_ERROR rather than
        // H3_REQUEST_REJECTED (RFC 9114 §8.1): the request was not rejected on its merits, the server
        // lost track of which table owns it — and §8.1 reserves "rejected" for a request the peer may
        // safely retry, which this one is.
        guard let plan = scope.registry.plan(for: id) else {
            await retireHTTP3Stream(
                id,
                errorCode: HTTP3ErrorCode.h3InternalError.rawValue,
                in: scope
            )
            return nil
        }
        // Resolve the WebSocket route for this path against that generation; CSWSH defense
        // (RFC 6455 §10.2): a disallowed Origin refuses the tunnel, as on the h1/h2 paths.
        guard proto == "websocket",
            let handler = plan.snapshot.resolver?
                .match(method: request.method, path: request.path, isUpgrade: true)?
                .route.webSocketHandler,
            handler.shouldUpgrade(request),
            handler.isOriginAllowed(request.headerFields[.origin])
        else {
            // Through the funnel (R5-P0c). The engine recorded this stream as a tunnel the moment the
            // Extended CONNECT decoded, and it never drops a tunnel record on its own — so a bare
            // `stream.reset` here left one record per refused handshake for the life of the
            // connection, which is a free lever for anyone who can reach a WebSocket path.
            await retireHTTP3Stream(
                id,
                errorCode: HTTP3ErrorCode.h3RequestRejected.rawValue,
                in: scope
            )
            return nil
        }
        let permessageDeflate = WebSocketHandshake.negotiatePermessageDeflate(request.headerFields)
        guard
            let accept = await scope.engine.acceptTunnel(
                id, secWebSocketExtensions: permessageDeflate?.headerValue
            ),
            (try? await stream.send(accept, fin: false)) != nil
        else {
            await retireHTTP3Stream(
                id,
                errorCode: HTTP3ErrorCode.h3InternalError.rawValue,
                in: scope
            )
            return nil
        }
        let cap = limits.effectiveWebSocketMessageSize
        let socket = WebSocketConnection(maxMessageSize: cap, permessageDeflate: permessageDeflate)
        return (socket, handler)
    }

    /// Feeds tunnel `bytes` to the stream's ``WebSocketConnection`` and writes the frames it produces back
    /// as tunnel DATA (RFC 9220 over RFC 6455 §6).
    ///
    /// Returns the updated connection, or nil once it closes — after flushing the queued Close and FINing
    /// the stream (a violation leaves a queued Close and sets `isClosing`).
    private func pumpHTTP3Tunnel(
        _ webSocket: WebSocketConnection?,
        handler: (any WebSocketHandler)?,
        bytes: [UInt8],
        on stream: any QUICStream,
        engine: Engine
    ) async -> WebSocketConnection? {
        guard var socket = webSocket, let handler else {
            return webSocket
        }
        let events = (try? socket.receive(bytes)) ?? []
        for event in events {
            for action in await handler.handle(event) { socket.apply(action) }
        }
        let outbound = socket.outboundBytes()
        if !outbound.isEmpty {
            let frame = await engine.sendTunnelData(stream.id, outbound)
            try? await stream.send(frame, fin: false)
        }
        guard !socket.isClosing else {
            await engine.closeTunnel(stream.id)
            try? await stream.send([], fin: true)
            return nil
        }
        return socket
    }
}
