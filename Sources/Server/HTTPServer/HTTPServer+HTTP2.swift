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
        // Advertise Extended CONNECT (RFC 8441 §3) only when a WebSocket handler can service it.
        var settings = HTTP2Settings()
        settings.enableConnectProtocol = webSocketHandler != nil
        var engine = HTTP2Connection(localSettings: settings, limits: limits)
        // Per-stream WebSocket engines for active WebSocket-over-HTTP/2 tunnels (RFC 8441).
        var webSockets: [HTTP2StreamID: WebSocketConnection] = [:]
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
                    let response = await responder.respond(to: request, body: body)
                    do {
                        // `withAltSvc` advertises HTTP/3 (RFC 7838) when a QUIC listener is running.
                        try engine.respond(
                            to: streamID, withAltSvc(response.head), body: response.body
                        )
                    }
                    catch {
                        // A connection-level fault (e.g. responding to an unknown stream) is fatal:
                        // flush the engine's queued GOAWAY (RFC 9113 §6.8) and close. A stream-level
                        // fault is contained — the engine queued RST_STREAM, flushed with this batch
                        // below — so other streams keep being served.
                        if error.isConnectionError {
                            let goAway = engine.outboundBytes()
                            if !goAway.isEmpty { try? await connection.send(goAway) }
                            return
                        }
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
