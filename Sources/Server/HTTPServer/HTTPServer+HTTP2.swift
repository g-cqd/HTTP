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
        // Whether the matched route streams its request body (Phase 1.4) — the engine then surfaces the
        // body incrementally (requestHead/requestBodyChunk/requestEnd) instead of one buffered request.
        let resolveStreamsBody: @Sendable (HTTPRequest) -> Bool = { [self] request in
            currentResolver?.resolve(method: request.method, path: request.path)?.streamsBody
                ?? false
        }
        var engine = HTTP2Connection(
            localSettings: settings,
            limits: limits,
            resolveBodyLimit: resolveBodyLimit,
            resolveStreamsBody: resolveStreamsBody
        )
        // Per-stream WebSocket tunnels (engine + resolved handler) for active WebSocket-over-HTTP/2
        // streams (RFC 8441) — a single connection can multiplex tunnels to different WebSocket routes.
        var webSockets: [HTTP2StreamID: HTTP2WebSocketTunnel] = [:]
        // In-flight streaming-route requests (Phase 1.4): each feeds an incremental body stream the
        // handler consumes; the response is sent at its `requestEnd`.
        var streaming: [HTTP2StreamID: HTTP2StreamingRequest] = [:]
        defer {
            // Connection closing: end every in-flight body stream and cancel its handler (no response
            // can still be sent), so no streaming request task or continuation leaks.
            for pending in streaming.values {
                pending.continuation.finish()
                pending.task.cancel()
            }
        }
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
            // Returns true on a connection-fatal fault (GOAWAY queued + flushed) — close the connection.
            if await serveHTTP2Events(
                events,
                engine: &engine,
                connection: connection,
                deadline: deadline,
                webSockets: &webSockets,
                streaming: &streaming
            ) {
                await closeRemainingTunnels(&webSockets)
                return
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
        await closeRemainingTunnels(&webSockets)
    }

    /// Fires the lifecycle close hook for every tunnel still open when the connection ends, so
    /// `onClose` is exactly-once for every session however the connection dies (RFC 6455 §7).
    private func closeRemainingTunnels(
        _ webSockets: inout [HTTP2StreamID: HTTP2WebSocketTunnel]
    ) async {
        let open = webSockets.values
        webSockets.removeAll()
        for tunnel in open {
            await tunnel.handler.onClose()
        }
    }
}
