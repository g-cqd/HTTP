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
}
