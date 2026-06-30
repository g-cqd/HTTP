//
//  HTTPServer+HTTP2.swift
//  HTTPServer
//
//  The server's HTTP/2 (RFC 9113) serve loop: drive the sans-I/O HTTP2Connection over a transport
//  connection — feed octets → events → respond → flush — until EOF, a timeout, a connection-level
//  protocol error, or a graceful shutdown drains the in-flight streams (RFC 9113 §6.8). Split out of
//  HTTPServer.swift so the runtime file stays focused (mirrors +HTTP3 / +WebSocket / +Chunked).
//

internal import HTTP2
internal import HTTPCore
internal import HTTPTransport
internal import WebSocket

extension HTTPServer {
    /// Drives the sans-I/O ``HTTP2Connection`` over `connection`: feed octets → events → respond →
    /// flush, looping until EOF, a timeout, or a connection-level protocol error.
    func serveHTTP2(
        _ connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        initialBytes: [UInt8]
    ) async {
        // Advertise Extended CONNECT (RFC 8441 §3) only when the responder declares a WebSocket route.
        var settings = HTTP2Settings()
        settings.enableConnectProtocol = currentResolver?.hasWebSocketRoutes ?? false
        // The matched route's body limit, resolved from each request head before its DATA is buffered
        // (Phase 1.2); `nil` when the responder is not a router or the route declares no limit.
        let resolveBodyLimit: @Sendable (HTTPRequest) -> Int? = { [self] request in
            currentResolver?.resolve(method: request.method, path: request.path)?.bodyLimit
        }
        var engine = HTTP2Connection(
            localSettings: settings, limits: limits, resolveBodyLimit: resolveBodyLimit
        )
        // Per-stream WebSocket tunnels (engine + resolved handler) for active WebSocket-over-HTTP/2
        // streams (RFC 8441) — a single connection can multiplex tunnels to different WebSocket routes.
        var webSockets: [HTTP2StreamID: HTTP2WebSocketTunnel] = [:]
        var inbound = initialBytes
        var sentGoAway = false  // graceful shutdown queues GOAWAY once (RFC 9113 §6.8)
        while true {
            let events: [HTTP2Connection.Event]
            do {
                events = try engine.receive(inbound)
            }
            catch {
                // Connection-level protocol error: the engine queued a GOAWAY (RFC 9113 §6.8) — send
                // it best-effort so the peer learns the cause, then close.
                let goAway = engine.outboundBytes()
                if !goAway.isEmpty { try? await connection.send(goAway) }
                break
            }
            inbound = []
            for event in events {
                if case .request(let streamID, let request, let body) = event {
                    // Native streaming (P6b) when the response has a body stream, else buffered; either
                    // returns true on a connection-fatal fault (GOAWAY queued + flushed), so close.
                    if await respondToRequest(
                        streamID: streamID,
                        request: request,
                        body: body,
                        engine: &engine,
                        connection: connection,
                        deadline: deadline
                    ) {
                        return
                    }
                }
                else {
                    await handleHTTP2Tunnel(event, engine: &engine, webSockets: &webSockets)
                }
            }
            queueGoAwayIfDraining(&engine, &sentGoAway)  // RFC 9113 §6.8 graceful shutdown
            let outbound = engine.outboundBytes()
            if !outbound.isEmpty {
                do { try await connection.send(outbound) }
                catch { break }
            }
            if drainComplete(sentGoAway, engine) {
                break  // GOAWAY sent and all in-flight streams drained — close
            }
            deadline.arm(clock.now.advanced(by: limits.idleTimeout))
            let chunk = try? await connection.receive(maxLength: 16_384)
            deadline.disarm()
            guard let chunk, !chunk.isEmpty else { break }
            inbound = chunk
        }
    }
}
