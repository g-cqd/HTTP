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
        engine: Engine,
        webSocket: inout WebSocketConnection?,
        tunnelHandler: inout (any WebSocketHandler)?
    ) async {
        switch event {
            case .extendedConnect(let id, let request, let proto):
                let tunnel = await acceptHTTP3Tunnel(
                    id, request: request, protocol: proto, on: stream, engine: engine
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
    private func acceptHTTP3Tunnel(
        _ id: QUICStreamID,
        request: HTTPRequest,
        protocol proto: String,
        on stream: any QUICStream,
        engine: Engine
    ) async -> (socket: WebSocketConnection, handler: any WebSocketHandler)? {
        // Resolve the WebSocket route for this path; CSWSH defense (RFC 6455 §10.2): a disallowed Origin
        // refuses the tunnel, as on the h1/h2 paths.
        guard proto == "websocket",
            let handler = currentResolver?.resolveWebSocket(path: request.path)?.webSocketHandler,
            handler.shouldUpgrade(request),
            handler.isOriginAllowed(request.headerFields[.origin])
        else {
            stream.reset(errorCode: HTTP3ErrorCode.h3RequestRejected.rawValue)
            return nil
        }
        let permessageDeflate = WebSocketHandshake.negotiatePermessageDeflate(request.headerFields)
        guard
            let accept = await engine.acceptTunnel(
                id, secWebSocketExtensions: permessageDeflate?.headerValue
            ),
            (try? await stream.send(accept, fin: false)) != nil
        else {
            stream.reset(errorCode: HTTP3ErrorCode.h3InternalError.rawValue)
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
