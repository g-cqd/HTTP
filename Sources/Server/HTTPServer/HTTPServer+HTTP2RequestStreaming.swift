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
//  ever block on a handler. The backpressure therefore cannot be "the producer waits" — it is "the peer
//  is not given more window": each chunk goes into a ``BoundedByteChannel`` with `trySend`, the handler's
//  iterator reports what it takes, and the consumer credits the receive windows from that report
//  (2026-07-31 audit F4, ADR 0006). Memory is bounded by ``HTTPLimits/streamReceiveWindow`` per stream
//  and ``HTTPLimits/connectionReceiveWindow`` per connection — by handler consumption, not by the
//  per-route body cap, which the streaming path never had a connection-level aggregate for.
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
        state: inout HTTP2ConnectionState,
        connection: any TransportConnection,
        group: inout DiscardingTaskGroup,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async {
        switch event {
            case .request(let streamID, let request, let body):
                let responder = currentResponder  // hot-swappable responder, read once (G4a)
                state.pendingRequests += 1
                group.addTask { [self] in
                    let context = RequestContext(connection: connection, request: request)
                    let response = await responder.respond(
                        to: request, body: requestBody(body, for: request), context: context
                    )
                    continuation.yield(.requestReady(streamID, response))
                }
            case .requestHead(let streamID, let request):
                state.streaming[streamID] = beginHTTP2StreamingRequest(
                    request: request,
                    streamID: streamID,
                    connection: connection,
                    group: &group,
                    reporting: &state.consumption,
                    pendingRequests: &state.pendingRequests,
                    into: continuation
                )
            case .requestBodyChunk(let streamID, let bytes):
                await pushHTTP2BodyChunk(streamID, bytes: bytes, state: &state)
            case .requestEnd(let streamID):
                await endHTTP2StreamingRequest(streamID, streaming: &state.streaming)
            default:
                handleHTTP2Tunnel(event, state: &state, group: &group, into: continuation)
        }
    }

    /// Hands one decoded DATA chunk to the handler's body channel — never blocking the consumer.
    ///
    /// `trySend` rather than `send`: the consumer is the engine's single owner, and parking it here would
    /// stop it processing the very WINDOW_UPDATE that unblocks the connection. A refusal is a hard error
    /// escalated to RST_STREAM, never a silent drop — a drop policy is never valid for transport octets,
    /// and a lost body chunk is indistinguishable from a truncated upload to the handler.
    ///
    /// It is unreachable on a well-formed connection: the stream's receive window is debited on arrival
    /// and credited only as this channel drains, so the peer can never have more in flight than the
    /// channel holds. It stands as defense in depth that fails closed (RFC 9113 §6.9).
    private func pushHTTP2BodyChunk(
        _ streamID: HTTP2StreamID,
        bytes: [UInt8],
        state: inout HTTP2ConnectionState
    ) async {
        guard let pending = state.streaming[streamID] else {
            return  // the stream was reset or ended out from under this chunk
        }
        guard await pending.channel.trySend(bytes) != .refused else {
            state.streaming.removeValue(forKey: streamID)
            await pending.channel.abandon()
            try? state.engine.abortResponse(to: streamID, code: .flowControlError)
            state.retire(streamID)
            return
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
        reporting consumption: inout [HTTP2StreamID: HTTP2ConsumptionSignal],
        pendingRequests: inout Int,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) -> HTTP2StreamingRequest {
        let channel = makeHTTP2GatedChannel()
        let signal = HTTP2ConsumptionSignal { continuation.yield(.consumed(streamID)) }
        consumption[streamID] = signal
        let context = RequestContext(connection: connection, request: request)
        let current = currentResponder  // hot-swappable responder, read once (G4a)
        pendingRequests += 1
        group.addTask {
            let body = HTTPRequestBodyStream(channel: channel, signal: signal)
            let response = await current.respond(to: request, body: .stream(body), context: context)
            continuation.yield(.requestReady(streamID, response))
        }
        return HTTP2StreamingRequest(channel: channel, signal: signal)
    }

    /// Ends a streaming request's body stream; its handler's response arrives later as a `.requestReady`
    /// wakeup (the task dispatched in ``beginHTTP2StreamingRequest`` self-reports on completion), so a
    /// slow streaming-route handler no longer blocks the consumer from processing the connection's next
    /// inbound chunk either — the same class of fix FIX #3 already applied to buffered requests.
    ///
    /// The stream leaves `streaming` but is deliberately **not** retired: octets already queued are still
    /// unconsumed, and returning their credit now would let the peer open fresh streams against memory
    /// this handler is still holding. `retire` happens at `.requestReady`, once nothing can consume the
    /// body any more (RFC 9113 §6.9).
    private func endHTTP2StreamingRequest(
        _ streamID: HTTP2StreamID,
        streaming: inout [HTTP2StreamID: HTTP2StreamingRequest]
    ) async {
        guard let pending = streaming.removeValue(forKey: streamID) else {
            return
        }
        await pending.channel.finish()
    }

    /// A consumption-gated intake channel for one HTTP/2 stream.
    ///
    /// The byte watermark IS ``HTTPLimits/streamReceiveWindow``: the engine will not admit more than a
    /// window of unconsumed DATA, so a channel bounded at exactly that can always accept what arrives and
    /// needs no second, parallel accounting (ADR 0006). The chunk cap is derived from the same window
    /// rather than from the transport knob, so a peer dribbling tiny DATA frames cannot exhaust the
    /// ticket count before it exhausts the window; coalescing keeps that count near its floor, and is
    /// safe here because both consumers (a request body, a WebSocket frame parser) read octets rather
    /// than messages.
    func makeHTTP2GatedChannel() -> BoundedByteChannel {
        let window = max(1, limits.streamReceiveWindow)
        return BoundedByteChannel(
            highWatermark: window,
            lowWatermark: window / 2,
            maxQueuedChunks: max(limits.maxQueuedInboundChunks, window / 4_096 + 2),
            coalescingBelow: 4 * 1_024
        )
    }
}
