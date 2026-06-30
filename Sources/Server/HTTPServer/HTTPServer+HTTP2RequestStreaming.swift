//
//  HTTPServer+HTTP2RequestStreaming.swift
//  HTTPServer
//
//  The HTTP/2 serve loop's per-event dispatch, including streaming-route request bodies (Phase 1.4). A
//  streaming route's body is delivered incrementally: the engine surfaces `requestHead` → a
//  `requestBodyChunk` per DATA frame → `requestEnd`, and the loop feeds each chunk into a non-blocking
//  ``HTTPRequestBodyStream`` the handler consumes, then sends the handler's response at `requestEnd`.
//
//  Unlike HTTP/3 (an independent QUIC stream per request, whose task can suspend on a back-pressured
//  handoff), HTTP/2 multiplexes every stream over one serve loop, so the loop must never block on a
//  handler — it yields chunks to an unbounded `AsyncStream` (memory bounded by the engine's per-route
//  body cap, not by handler consumption). Sub-limit back-pressure via consumption-gated window
//  replenishment is the documented HTTP/2 follow-up (ADR 0006).
//

internal import HTTP2
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Dispatches one batch of engine events — buffered requests, streaming-route request head/body/end,
    /// and tunnel events — returning true on a connection-fatal fault (GOAWAY queued + flushed).
    func serveHTTP2Events(
        _ events: [HTTP2Connection.Event],
        engine: inout HTTP2Connection,
        connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        webSockets: inout [HTTP2StreamID: HTTP2WebSocketTunnel],
        streaming: inout [HTTP2StreamID: HTTP2StreamingRequest]
    ) async -> Bool {
        for event in events {
            switch event {
                case .request(let streamID, let request, let body):
                    // Native streaming (P6b) when the response has a body stream, else buffered.
                    if await respondToRequest(
                        streamID: streamID,
                        request: request,
                        body: body,
                        engine: &engine,
                        connection: connection,
                        deadline: deadline
                    ) {
                        return true
                    }
                case .requestHead(let streamID, let request):
                    streaming[streamID] = beginHTTP2StreamingRequest(
                        request: request, connection: connection
                    )
                case .requestBodyChunk(let streamID, let bytes):
                    streaming[streamID]?.continuation.yield(bytes)
                case .requestEnd(let streamID):
                    if await endHTTP2StreamingRequest(
                        streamID,
                        engine: &engine,
                        connection: connection,
                        deadline: deadline,
                        streaming: &streaming
                    ) {
                        return true
                    }
                default:
                    await handleHTTP2Tunnel(event, engine: &engine, webSockets: &webSockets)
            }
        }
        return false
    }

    /// Begins a streaming-route request: an incremental body stream the loop feeds, and a task running
    /// the handler over it.
    ///
    /// The response is sent at `requestEnd`.
    private func beginHTTP2StreamingRequest(
        request: HTTPRequest, connection: any TransportConnection
    ) -> HTTP2StreamingRequest {
        let (stream, continuation) = AsyncStream.makeStream(of: [UInt8].self)
        let context = RequestContext(connection: connection, request: request)
        let current = currentResponder  // hot-swappable responder, read once (G4a)
        let task = Task {
            await current.respond(
                to: request, body: .stream(HTTPRequestBodyStream(stream)), context: context
            )
        }
        return HTTP2StreamingRequest(continuation: continuation, task: task)
    }

    /// Ends a streaming request's body, awaits its handler, and sends the response on `streamID` —
    /// returning true on a connection-fatal fault.
    private func endHTTP2StreamingRequest(
        _ streamID: HTTP2StreamID,
        engine: inout HTTP2Connection,
        connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        streaming: inout [HTTP2StreamID: HTTP2StreamingRequest]
    ) async -> Bool {
        guard let pending = streaming.removeValue(forKey: streamID) else {
            return false
        }
        pending.continuation.finish()
        let response = await pending.task.value
        return await sendHTTP2Response(
            streamID: streamID,
            response: response,
            engine: &engine,
            connection: connection,
            deadline: deadline
        )
    }
}
