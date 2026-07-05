//
//  HTTPServer+HTTP2RequestStreaming.swift
//  HTTPServer
//
//  The HTTP/2 merged-mailbox consumer's per-event dispatch, including streaming-route request bodies
//  (Phase 1.4). A streaming route's body is delivered incrementally: the engine surfaces `requestHead` →
//  a `requestBodyChunk` per DATA frame → `requestEnd`, and the consumer feeds each chunk into a
//  non-blocking ``HTTPRequestBodyStream`` the handler consumes, dispatched to its own task group child so
//  a slow handler here cannot stall the consumer either (unified with the buffered-request path below).
//
//  Unlike HTTP/3 (an independent QUIC stream per request, whose task can suspend on a back-pressured
//  handoff), HTTP/2 multiplexes every stream over one connection, so no task that feeds this consumer may
//  ever block on a handler — it yields chunks to an unbounded `AsyncStream` (memory bounded by the
//  engine's per-route body cap, not by handler consumption). Sub-limit back-pressure via consumption-gated
//  window replenishment is the documented HTTP/2 follow-up (ADR 0006).
//

internal import HTTP2
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Handles one engine event: dispatches a request's (buffered or streaming-route) handler and a
    /// tunnel's pump off the consumer, entirely through task-group children and the shared mailbox —
    /// every engine mutation (`respond`/`acceptTunnel`/etc.) happens only when this consumer later
    /// processes the resulting wakeup, keeping the engine and `connection.send` single-owner throughout.
    ///
    /// `pendingRequests` counts dispatched-but-not-yet-`.requestReady` handler tasks (buffered AND
    /// streaming-route), incremented here on dispatch — the consumer's EOF drain check
    /// (``HTTPServer/serveHTTP2(_:deadline:initialBytes:)``'s `.closed` case) reads it to know whether a
    /// request that was already fully received might still be mid-flight and worth letting finish before
    /// the connection actually closes, rather than cancelling it out from under itself.
    func handleHTTP2Event(
        _ event: HTTP2Connection.Event,
        engine: inout HTTP2Connection,
        connection: any TransportConnection,
        group: inout DiscardingTaskGroup,
        webSockets: inout [HTTP2StreamID: HTTP2WebSocketTunnel],
        streaming: inout [HTTP2StreamID: HTTP2StreamingRequest],
        pendingRequests: inout Int,
        pendingTunnels: inout Int,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) {
        switch event {
            case .request(let streamID, let request, let body):
                let responder = currentResponder  // hot-swappable responder, read once (G4a)
                pendingRequests += 1
                group.addTask { [self] in
                    let context = RequestContext(connection: connection, request: request)
                    let response = await responder.respond(
                        to: request, body: requestBody(body, for: request), context: context
                    )
                    continuation.yield(.requestReady(streamID, response))
                }
            case .requestHead(let streamID, let request):
                streaming[streamID] = beginHTTP2StreamingRequest(
                    request: request,
                    streamID: streamID,
                    connection: connection,
                    group: &group,
                    pendingRequests: &pendingRequests,
                    into: continuation
                )
            case .requestBodyChunk(let streamID, let bytes):
                streaming[streamID]?.continuation.yield(bytes)
            case .requestEnd(let streamID):
                endHTTP2StreamingRequest(streamID, streaming: &streaming)
            default:
                handleHTTP2Tunnel(
                    event,
                    engine: &engine,
                    group: &group,
                    webSockets: &webSockets,
                    pendingTunnels: &pendingTunnels,
                    into: continuation
                )
        }
    }

    /// Begins a streaming-route request: an incremental body stream the consumer feeds, and a task
    /// group child running the handler over it, which self-reports its ``ServerResponse`` back as a
    /// `.requestReady` wakeup once it finishes — unified with the buffered-request path (the response is
    /// APPLIED to the engine only later, when the consumer processes that wakeup).
    private func beginHTTP2StreamingRequest(
        request: HTTPRequest,
        streamID: HTTP2StreamID,
        connection: any TransportConnection,
        group: inout DiscardingTaskGroup,
        pendingRequests: inout Int,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) -> HTTP2StreamingRequest {
        let (stream, bodyContinuation) = AsyncStream.makeStream(of: [UInt8].self)
        let context = RequestContext(connection: connection, request: request)
        let current = currentResponder  // hot-swappable responder, read once (G4a)
        pendingRequests += 1
        group.addTask {
            let response = await current.respond(
                to: request, body: .stream(HTTPRequestBodyStream(stream)), context: context
            )
            continuation.yield(.requestReady(streamID, response))
        }
        return HTTP2StreamingRequest(continuation: bodyContinuation)
    }

    /// Ends a streaming request's body stream; its handler's response arrives later as a `.requestReady`
    /// wakeup (the task dispatched in ``beginHTTP2StreamingRequest`` self-reports on completion), so a
    /// slow streaming-route handler no longer blocks the consumer from processing the connection's next
    /// inbound chunk either — the same class of fix FIX #3 already applied to buffered requests.
    private func endHTTP2StreamingRequest(
        _ streamID: HTTP2StreamID,
        streaming: inout [HTTP2StreamID: HTTP2StreamingRequest]
    ) {
        guard let pending = streaming.removeValue(forKey: streamID) else {
            return
        }
        pending.continuation.finish()
    }
}
