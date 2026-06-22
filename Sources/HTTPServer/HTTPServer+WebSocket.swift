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
        request: HTTPRequest,
        handler: any WebSocketHandler,
        carryover: [UInt8]
    ) async {
        // Cross-site WebSocket hijacking defense (RFC 6455 §10.2, CWE-1385): the handshake is exempt
        // from the Same-Origin Policy and CORS, so reject a disallowed Origin with 403 before
        // completing the upgrade. The default policy admits any origin; apps allowlist via the handler.
        guard handler.isOriginAllowed(request.headerFields[.origin]) else {
            let rejection = ResponseSerializer.serialize(HTTPResponse(status: .forbidden))
            try? await connection.send(rejection)
            return
        }
        let accepted: HTTPResponse
        do {
            accepted = try WebSocketHandshake.response(to: request)
        } catch {
            let rejection = ResponseSerializer.serialize(
                HTTPResponse(status: error.rejectionStatus))
            try? await connection.send(rejection)
            return
        }
        guard (try? await connection.send(ResponseSerializer.serialize(accepted))) != nil else {
            return
        }
        await driveWebSocket(connection, handler: handler, carryover: carryover)
    }

    /// Pumps the ``WebSocketConnection`` over `connection`: receive → events → handler actions →
    /// flush, looping until a Close is sent, EOF, an idle timeout, or a send failure (RFC 6455 §6).
    private func driveWebSocket(
        _ connection: any TransportConnection,
        handler: any WebSocketHandler,
        carryover: [UInt8]
    ) async {
        var engine = WebSocketConnection(maxMessageSize: limits.maxBodySize)
        var inbound = carryover
        while true {
            var failed = false
            do {
                for event in try engine.receive(inbound) {
                    for action in await handler.handle(event) { engine.apply(action) }
                }
            } catch {
                // The engine queued a Close with the mapped code; flush it below, then stop.
                failed = true
            }
            inbound = []
            let outbound = engine.outboundBytes()
            if !outbound.isEmpty, (try? await connection.send(outbound)) == nil { break }
            if failed || engine.isClosing { break }

            let chunk: [UInt8]? = try? await withTimeout(limits.keepAliveTimeout) {
                try await connection.receive(maxLength: 16_384)
            }
            guard let chunk, !chunk.isEmpty else { break }  // EOF, idle timeout, or read failure
            inbound = chunk
        }
        await connection.close()
    }

    // MARK: WebSocket over HTTP/2 (RFC 8441 / RFC 9220)

    /// Dispatches a tunnel event from the HTTP/2 engine for a WebSocket-over-HTTP/2 stream: accept an
    /// Extended CONNECT (RFC 8441 §4), pump tunnel DATA through that stream's WebSocket engine, and
    /// tear the stream down on close or reset.
    func handleHTTP2Tunnel(
        _ event: HTTP2Connection.Event,
        engine: inout HTTP2Connection,
        webSockets: inout [HTTP2StreamID: WebSocketConnection]
    ) async {
        guard let handler = webSocketHandler else { return }
        switch event {
        case .extendedConnect(let streamID, let request, let proto):
            // Same CSWSH defense as the h1 path (RFC 6455 §10.2): a disallowed Origin refuses the
            // tunnel, treated like a declined upgrade.
            guard proto == "websocket", handler.shouldUpgrade(request),
                handler.isOriginAllowed(request.headerFields[.origin])
            else { return }
            try? engine.acceptTunnel(streamID)  // 200, no END_STREAM (RFC 8441 §5)
            webSockets[streamID] = WebSocketConnection(maxMessageSize: limits.maxBodySize)
        case .tunnelData(let streamID, let bytes):
            guard var socket = webSockets[streamID] else { return }
            await driveTunnel(
                &socket, bytes: bytes, streamID: streamID, engine: &engine, handler: handler)
            if socket.isClosing {
                try? engine.closeTunnel(streamID)
                webSockets[streamID] = nil
            } else {
                webSockets[streamID] = socket
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
