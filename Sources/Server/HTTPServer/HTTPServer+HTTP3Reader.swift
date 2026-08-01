//
//  HTTPServer+HTTP3Reader.swift
//  HTTPServer
//
//  The two halves of an HTTP/3 request stream's serve loop that stopped fitting inside it once the
//  loop gained a second work source (audit REG-2): the reader task that owns `stream.receive()`, and
//  the application of one batch of the stream's own engine events.
//
//  Why a reader task at all. A stream must react to inbound QUIC octets *and* to routed engine events
//  another stream's task produced for it — RFC 9204 §2.1.2, an encoder-stream insert unblocking this
//  stream's field section. `receive()` cannot be raced: cancelling a half-finished transport read would
//  discard octets. So the read is moved to its own task that hands each chunk to
//  ``HTTP3StreamInbox``, and the serve loop waits on that inbox, which merges both sources.
//
//  The reader parks while the loop still holds the previous chunk, so exactly one chunk is ever in
//  flight and QUIC flow control back-pressures the peer — the loop's pace is the reader's pace, as it
//  was when the loop called `receive()` itself.
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport
internal import WebSocket

extension HTTPServer {
    /// Reads `stream` and hands each chunk to the serve loop's inbox until FIN, EOF, or teardown.
    ///
    /// Ends the inbox on every exit — a receive fault, the peer's EOF, the FIN, or a refused offer —
    /// so a loop parked in ``HTTP3StreamInbox/next()`` always unwinds.
    static func pumpHTTP3Inbound(_ stream: any QUICStream, into inbox: HTTP3StreamInbox) async {
        defer { inbox.close() }
        while let chunk = try? await stream.receive() {
            // A refused offer means the inbox closed under us; the FIN means there is nothing after it.
            guard await inbox.offer(chunk.bytes, fin: chunk.fin), !chunk.fin else {
                return
            }
        }
    }

    /// Acts on one batch of this stream's own engine events, in the order the engine surfaced them.
    ///
    /// - Returns: how the stream ended if a streaming route (Phase 1.4) or a rival claim took it over,
    ///   in which case the serve loop is finished; `nil` while the loop should keep reading.
    func applyHTTP3StreamEvents(
        _ events: [HTTP3Connection.Event],
        stream: any QUICStream,
        inbox: HTTP3StreamInbox,
        in scope: HTTP3ConnectionScope,
        webSocket: inout WebSocketConnection?,
        tunnelHandler: inout (any WebSocketHandler)?
    ) async -> HTTP3StreamExit? {
        for (index, event) in events.enumerated() {
            switch event {
                case .request(let id, let request, let body):
                    await answerHTTP3Request(
                        id,
                        request: request,
                        body: body,
                        stream: stream,
                        in: scope
                    )
                case .requestHead(let id, let request):
                    // A streaming route (Phase 1.4) takes over this stream for its lifetime: feed the
                    // body off the wire into the handler's stream, then send its response.
                    guard scope.registry.claim(id) != nil else {
                        return .answered  // another driver claimed it; this one owes nothing
                    }
                    return await serveHTTP3StreamingRequest(
                        id,
                        request: request,
                        buffered: Self.trailingBody(of: events, after: index),
                        stream: stream,
                        inbox: inbox,
                        in: scope
                    )
                case .requestBodyChunk, .requestEnd:
                    break  // consumed by serveHTTP3StreamingRequest — never standalone here
                case .extendedConnect, .tunnelData, .tunnelClosed:
                    await handleHTTP3TunnelEvent(
                        event,
                        stream: stream,
                        in: scope,
                        webSocket: &webSocket,
                        tunnelHandler: &tunnelHandler
                    )
                case .goAway:
                    break
            }
        }
        return nil
    }
}
