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
    /// tunnel's pump off the consumer, entirely through ``HTTP2StreamTasks`` and the shared mailbox —
    /// every engine mutation (`respond`/`acceptTunnel`/etc.) happens only when this consumer later
    /// processes the resulting wakeup, keeping the engine and `connection.send` single-owner throughout.
    ///
    /// `state.tasks` records the streams whose work has started and not yet reported back (buffered,
    /// streaming-route, and tunnel alike). The consumer's EOF drain reads it to know whether a request
    /// that was already fully received might still be mid-flight and worth letting finish, rather than
    /// cancelling it out from under itself; ``resetHTTP2Stream(_:state:)`` cancels through it; and
    /// ``HTTP2StreamTasks/shutdown()`` joins on it when the connection closes.
    ///
    /// The switch is deliberately EXHAUSTIVE over `HTTP2Connection.Event`. It used to end in `default:`,
    /// which silently routed `.streamReset` into the tunnel handler — the whole of audit finding 6.
    /// Listing every case makes a future event a compile error instead of a misroute.
    func handleHTTP2Event(
        _ event: HTTP2Connection.Event,
        state: inout HTTP2ConnectionState,
        connection: any TransportConnection,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async {
        switch event {
            case .request(let streamID, let inbound, let body):
                // The plan this stream's HEADERS resolved: its generation and its route match, filed
                // by the engine's `resolveRoute` and taken here, so the table is walked once for the
                // whole request (CR-F19) and the body limit already enforced against it and the
                // handler about to run belong to the same generation (CR-F12).
                let plan =
                    state.plans.plan(for: streamID) ?? DispatchPlan(snapshot: currentSnapshot)
                // The ingress seam (audit CR-F13): both halves are bound `let` here so the sanitized
                // request — never the inbound one — is what the dispatched task captures.
                let (request, context) = RequestContext.ingress(
                    inbound, over: connection, matching: plan.match
                )
                dispatchHTTP2Request(
                    request,
                    body: requestBody(body, following: plan),
                    context: context,
                    streamID: streamID,
                    plan: plan,
                    connection: connection,
                    tasks: state.tasks,
                    into: continuation
                )
            case .requestHead(let streamID, let request):
                state.streaming[streamID] = beginHTTP2StreamingRequest(
                    request: request,
                    streamID: streamID,
                    connection: connection,
                    plan: state.plans.plan(for: streamID)
                        ?? DispatchPlan(snapshot: currentSnapshot),
                    reporting: &state.consumption,
                    tasks: state.tasks,
                    into: continuation
                )
            case .requestBodyChunk(let streamID, let bytes):
                await pushHTTP2BodyChunk(streamID, bytes: bytes, state: &state)
            case .requestEnd(let streamID):
                await endHTTP2StreamingRequest(streamID, streaming: &state.streaming)
            case .streamReset(let streamID, _):
                await resetHTTP2Stream(streamID, state: &state)
            case .extendedConnect, .tunnelData, .tunnelClosed:
                await handleHTTP2Tunnel(event, state: &state, into: continuation)
        }
    }

    /// Dispatches a BUFFERED request's handler off the consumer, with a handle the peer can cancel.
    ///
    /// Seam 3 of 6 (audit CR-F7). The `.requestReady` yield is the pre-existing return-to-owner
    /// mechanism: the response is APPLIED to the engine only when the single mailbox consumer processes
    /// that wakeup, so HPACK state, flow control and `connection.send` keep one owner whatever executor
    /// this handler ran on. It is yielded from inside the task, unconditionally, so a cancelled handler
    /// still reports back and the accounting still returns to zero.
    ///
    /// An unstructured `Task` *instead of* a task-group child, not inside one (R5-P0d). Swift offers no
    /// way to cancel one child of a group, so a per-stream cancel handle needs an unstructured task
    /// somewhere; nesting one inside a child — finding 6's shape, and the shape whose cost that finding
    /// cited when it deferred this path — pays for two tasks per request. Dispatching one measures
    /// identical to no cancellation at all (`http2/dispatch/buffered-*`). The lifetime is not lost:
    /// ``HTTP2StreamTasks/shutdown()`` cancels and awaits every one of these before `serveHTTP2`
    /// returns, which is the join the group used to perform.
    ///
    /// The executor preference is restored explicitly because an unstructured `Task` does not inherit
    /// it (ADR 0007): without it, giving this seam a cancel handle would silently move every buffered
    /// HTTP/2 handler off the connection's reactor and quietly turn `.inline` into `.concurrent` here.
    /// It is skipped when the backbone has no preference, which is documented to be a no-op anyway, so
    /// the guarantee costs nothing on the backbones that cannot use it. The scope is the handler call
    /// alone, so `.concurrent` and `.adaptive` still hop from inside `respond` exactly as before.
    private func dispatchHTTP2Request(
        _ request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        streamID: HTTP2StreamID,
        plan: DispatchPlan,
        connection: any TransportConnection,
        tasks: HTTP2StreamTasks,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) {
        let work = Task { [self] in
            // Two spelled-out calls rather than one closure handed to a helper: an async closure
            // capturing the four request values costs a context box per request, and this is the
            // 200k-rps path. Measured — that box is the whole difference between +1 malloc and zero.
            let response: ServerResponse
            if let executor = connection.preferredTaskExecutor {
                response = await withTaskExecutorPreference(executor) {
                    await respond(to: request, body: body, context: context, following: plan)
                }
            }
            else {
                response = await respond(to: request, body: body, context: context, following: plan)
            }
            continuation.yield(.requestReady(streamID, response))
        }
        tasks.register(work, for: streamID)
    }

    /// Retires every per-stream obligation after the peer reset `streamID` (RFC 9113 §6.4).
    ///
    /// Audit finding 6: this event used to fall through `default:` into the tunnel handler, which only
    /// consults `state.webSockets`. For a streaming-route request that meant the body channel was
    /// neither ended nor removed, so the handler parked until the whole connection died, its receive
    /// credit was never returned, and the dispatch count never came back down.
    ///
    /// No RST_STREAM is sent back: the engine dropped the stream when it processed the peer's frame, and
    /// resetting an already-closed stream would both be pointless and charge our own Rapid Reset budget
    /// (CVE-2023-44487). The handler's `.requestReady` still arrives afterwards and is dropped by
    /// ``beginHTTP2Response``'s open-stream guard, which is what returns the accounting to zero.
    func resetHTTP2Stream(
        _ streamID: HTTP2StreamID,
        state: inout HTTP2ConnectionState
    ) async {
        await endHTTP2Stream(streamID, resettingWith: nil, state: &state)
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
            await endHTTP2Stream(streamID, resettingWith: .flowControlError, state: &state)
            return
        }
    }

    /// Tears down every per-stream obligation and resets the stream with `code` (RFC 9113 §6.4).
    ///
    /// The one teardown path for a stream the *server* decides to end — a `trySend` refusal, a swept
    /// stall — and the shape the peer-initiated reset path reuses. Centralized deliberately: a stream
    /// carries a body channel, a handler task, a consumption report, a stall count and receive credit,
    /// and forgetting any one of them on any one path is the exact class of defect the audit found (a
    /// handler parked forever, or credit lost from the shared connection window).
    ///
    /// `abandon` rather than `finish`: the stream is being reset, so the handler must observe truncation
    /// rather than a clean end of body.
    ///
    /// The RESPONSE side is retired here too (R5-P0d). Dropping a native-streaming relay's entry told
    /// neither its pump nor its producer anything, so both stayed parked for the rest of the
    /// connection's life; ``HTTP2ResponseRelay/abandon()`` reaches both parked positions.
    func endHTTP2Stream(
        _ streamID: HTTP2StreamID,
        resettingWith code: HTTP2ErrorCode?,
        state: inout HTTP2ConnectionState
    ) async {
        if let pending = state.streaming.removeValue(forKey: streamID) {
            await pending.channel.abandon()  // the handler's `for await` returns nil: truncation
        }
        if let tunnel = state.webSockets.removeValue(forKey: streamID) {
            await tunnel.channel.abandon()
        }
        if let relay = state.relays.removeValue(forKey: streamID) {
            await relay.abandon()
        }
        // ...and whatever this stream dispatched stops even if it was parked somewhere no channel
        // teardown reaches: a database call, a sleep, a lock, or a buffered handler with no channel.
        state.tasks.cancel(streamID)
        if let code {
            // Best-effort: a reset-budget overflow (MadeYouReset, CVE-2025-8671) has already queued the
            // engine's own GOAWAY, and this stream is going away either way.
            try? state.engine.abortResponse(to: streamID, code: code)
        }
        state.retire(streamID)
    }

    /// Begins a streaming-route request: an incremental body stream the consumer feeds, and a task
    /// group child running the handler over it, which self-reports its ``ServerResponse`` back as a
    /// `.requestReady` wakeup once it finishes — unified with the buffered-request path (the response is
    /// APPLIED to the engine only later, when the consumer processes that wakeup).
    private func beginHTTP2StreamingRequest(
        request inbound: HTTPRequest,
        streamID: HTTP2StreamID,
        connection: any TransportConnection,
        plan: DispatchPlan,
        reporting consumption: inout [HTTP2StreamID: HTTP2ConsumptionSignal],
        tasks: HTTP2StreamTasks,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) -> HTTP2StreamingRequest {
        let channel = makeHTTP2GatedChannel()
        let signal = HTTP2ConsumptionSignal { continuation.yield(.consumed(streamID)) }
        consumption[streamID] = signal
        // The ingress seam (audit CR-F13) — the sanitized request is what the handler task captures.
        let (request, context) = RequestContext.ingress(
            inbound, over: connection, matching: plan.match
        )
        let work = Task { [self] in
            // Seam 4 of 6 (audit CR-F7). `plan` carries this request's generation (CR-F12), so the
            // responder is still the one its HEADERS resolved; the policy only decides which executor
            // runs it. Consumption signalling and the `.requestReady` yield are unaffected — both are
            // lock-free and executor-agnostic by construction.
            //
            // No executor preference is restored here, unlike the buffered path: this seam has run off
            // the reactor since finding 6 dispatched it through an unstructured task, and ADR 0007
            // pins that.
            let body = HTTPRequestBodyStream(channel: channel, signal: signal)
            let response = await respond(
                to: request,
                body: .stream(body),
                context: context,
                following: plan
            )
            continuation.yield(.requestReady(streamID, response))
        }
        tasks.register(work, for: streamID)
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
