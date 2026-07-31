//
//  HTTPServer+RequestStreaming.swift
//  HTTPServer
//
//  The HTTP/1.1 streaming-request exchange (Phase 1.4, RFC 9112 §6/§7): dispatch the handler with an
//  incremental ``HTTPRequestBodyStream``, feed the body off the wire into it, then send the response.
//
//  The body is handed over one owned chunk at a time through a back-pressured ``AsyncHandoff`` — the
//  same rendezvous HTTP/3 uses, and for the same reason: HTTP/1.1 has no flow control of its own, so
//  the only backpressure available is the producer suspending until the handler takes a chunk, which
//  stops the reads, which closes the peer's TCP window. (HTTP/2's `BoundedByteChannel` +
//  consumption-signal machinery is deliberately *not* used here: it exists because h2 multiplexes many
//  streams over one serve loop that must never park on a handler. h1 has a dedicated reader task per
//  connection, so parking it is exactly the right thing.)
//
//  No body octet ever enters the connection's keep-alive buffer: a Content-Length body is read straight
//  into owned chunks sized `min(remaining, window)`, and a chunked body is framed inside a fixed
//  ``RequestBodyWindow`` (see HTTPServer+ChunkedStreaming). The body is *always* read to completion —
//  even when the handler abandons the stream — so the keep-alive cursor stays exact and a pipelined
//  follow-up is never desynced (audit CR-F5 / addendum P0.4).
//

internal import HTTP1
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer where C.Duration == Duration {
    /// Serves one streaming-route exchange (Phase 1.4): dispatch the handler with an incremental
    /// ``RequestBody/stream(_:)`` and feed the whole body off the wire into it, then send the response.
    ///
    /// `Expect: 100-continue` is honored before the body is read (RFC 9110 §10.1.1). The handler runs as
    /// a structured child (`async let`), so cancelling the connection reaps it; it abandons the handoff
    /// on return, which resumes the feed loop even when the handler never drained the body.
    ///
    /// A body that cannot be fully read (truncation, or a chunked body that overran the route limit
    /// after dispatch) **fails** the handoff rather than finishing it, and closes the connection: a
    /// handler must never be told a short body ended cleanly, which it cannot distinguish from a whole
    /// one (CWE-444), and a pipelined follow-up must never be framed from mid-body octets.
    func serveStreaming(
        _ connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        pending: PendingRequest,
        buffer: inout [UInt8],
        start: inout Int,
        responseBuffer: inout [UInt8],
        following plan: DispatchPlan
    ) async -> Bool {
        if await handleExpect(pending.head, on: connection) {
            return false  // a 417 was sent — the expectation cannot be met
        }
        // The ingress seam: the context, and the request with every client-supplied server-asserted
        // field stripped (audit CR-F13).
        let (request, context) = RequestContext.ingress(
            pending.head.request, over: connection, matching: plan.match
        )
        let handoff = AsyncHandoff()
        async let responseTask = respondStreaming(
            request, handoff: handoff, context: context, on: plan.snapshot.responder
        )
        let consumed = await produceBody(
            pending,
            into: handoff,
            buffer: &buffer,
            from: connection,
            deadline: deadline,
            bodyLimit: plan.bodyLimit
        )
        guard let consumed else {
            await handoff.fail()  // the handler's body ends WITHOUT a clean end-of-body
            _ = await responseTask  // reap the child before unwinding
            return false  // body truncated / over-limit mid-stream — close rather than desync
        }
        await handoff.finish()
        let response = await responseTask
        start = consumed
        return await sendStreamingResponse(
            response,
            to: pending,
            on: connection,
            deadline: deadline,
            responseBuffer: &responseBuffer
        )
    }

    /// Runs the handler over the body handoff, abandoning it on return.
    ///
    /// The abandon is what unblocks a feed loop parked on a full handoff slot when the handler returned
    /// without draining the body; the feed then runs to completion, dropping the rest.
    private func respondStreaming(
        _ request: HTTPRequest,
        handoff: AsyncHandoff,
        context: RequestContext,
        on responder: any HTTPResponder
    ) async -> ServerResponse {
        let response = await responder.respond(
            to: request, body: .stream(HTTPRequestBodyStream(handoff: handoff)), context: context
        )
        await handoff.abandon()
        return response
    }

    /// Sends a streaming exchange's response and reports whether the connection stays open.
    private func sendStreamingResponse(
        _ response: ServerResponse,
        to pending: PendingRequest,
        on connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        responseBuffer: inout [UInt8]
    ) async -> Bool {
        let request = pending.head.request
        var head = withAltSvc(response.head)
        let draining = applyHTTP1Drain(to: &head)
        if let stream = response.stream {
            let sent = await sendStreamedResponse(
                head,
                stream: stream,
                omitBody: request.method == .head,
                on: connection,
                deadline: deadline
            )
            guard sent, !draining else {
                return false
            }
            return !Self.shouldClose(
                version: pending.head.version, request: request, response: head
            )
        }
        let sendsBody = ResponseSerializer.serializeHead(
            head,
            bodyLength: response.body.count,
            omitBody: request.method == .head,
            into: &responseBuffer
        )
        // Bound the buffered response send by the idle deadline (FIX #1) — see ``serveOne``.
        deadline.arm(clock.now.advanced(by: limits.idleTimeout))
        do {
            if sendsBody {
                try await connection.send(responseBuffer, response.body)
            }
            else {
                try await connection.send(responseBuffer)
            }
        }
        catch {
            deadline.disarm()
            return false
        }
        deadline.disarm()
        if draining {
            return false
        }
        return !Self.shouldClose(version: pending.head.version, request: request, response: head)
    }

    /// Reads the whole request body off the wire, offering each chunk to `handoff` as it arrives, and
    /// returns the buffer index just past the consumed body — or `nil` if it could not be fully read
    /// (truncation, or a chunked body that overran the route limit).
    func produceBody(
        _ pending: PendingRequest,
        into handoff: AsyncHandoff,
        buffer: inout [UInt8],
        from connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        bodyLimit: Int?
    ) async -> Int? {
        switch pending.head.framing {
            case .none:
                return pending.bodyStart
            case .contentLength(let length):
                return await produceContentLengthBody(
                    length,
                    after: pending.bodyStart,
                    into: handoff,
                    buffer: &buffer,
                    from: connection,
                    deadline: deadline
                )
            case .chunked:
                return await produceChunkedBody(
                    pending,
                    into: handoff,
                    buffer: &buffer,
                    from: connection,
                    deadline: deadline,
                    bodyLimit: bodyLimit
                )
        }
    }

    /// Streams a Content-Length body (RFC 9112 §6.2), returning the index just past it — `nil` if the
    /// peer truncated it.
    ///
    /// A declared length needs no receive window: the remaining count *is* the read bound, so each read
    /// asks for `min(remaining, window)` and the owned array the transport returns is handed straight to
    /// the handler — one allocation per chunk, no copy, and never a byte more than the body (which is
    /// what keeps a pipelined follow-up out of it). The octets that arrived alongside the head are moved
    /// out of the connection buffer first, so from here the body never touches it at all.
    private func produceContentLengthBody(
        _ length: Int,
        after bodyStart: Int,
        into handoff: AsyncHandoff,
        buffer: inout [UInt8],
        from connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>
    ) async -> Int? {
        let carried = min(buffer.count - bodyStart, length)
        if carried > 0 {
            let prefix = Array(buffer[bodyStart ..< bodyStart + carried])
            buffer.removeSubrange(bodyStart ..< bodyStart + carried)
            await handoff.offer(prefix)
        }
        var remaining = length - carried
        let window = limits.effectiveRequestBodyWindow
        while remaining > 0 {
            deadline.arm(clock.now.advanced(by: limits.idleTimeout))
            let chunk = try? await connection.receive(maxLength: min(remaining, window))
            deadline.disarm()
            guard let chunk, !chunk.isEmpty else {
                return nil  // truncated before the declared length
            }
            remaining -= chunk.count
            await handoff.offer(chunk)  // ownership transfer — the producer parks until it is taken
        }
        return bodyStart
    }
}
