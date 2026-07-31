//
//  HTTPServer+HTTP3Streaming.swift
//  HTTPServer
//
//  The two streaming halves of the HTTP/3 runtime (RFC 9114 §4.1), split out of HTTPServer+HTTP3.swift
//  so the connection/stream driver file stays focused: a streaming *request* route, whose body is fed
//  off the wire into a back-pressured handoff the handler consumes (Phase 1.4), and a streaming
//  *response*, whose producer is pumped straight onto the QUIC stream as DATA frames (P6b).
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Drives a streaming-route request on its QUIC stream (Phase 1.4): feed the body off the wire into a
    /// back-pressured handoff the handler consumes, then send the handler's response on the same stream.
    ///
    /// The handler runs in a child task and consumes the body via the stream; the feed loop suspends on a
    /// full handoff slot until the handler takes each chunk (1-chunk backpressure), and QUIC's per-stream
    /// flow control back-pressures the sender in turn — bounded memory for an arbitrarily large upload.
    /// The handler abandons the handoff on return, so the feed loop resumes (dropping the rest) even if
    /// the handler did not drain the body; the whole body is still read off the wire to FIN.
    ///
    /// The body is only *complete* when the engine surfaced a `requestEnd` — QUIC's FIN, with the
    /// declared content-length validated against it (RFC 9114 §4.1 / §4.1.2). An EOF, a peer reset, or a
    /// receive failure leaves that unobserved, and the request is then refused with H3_REQUEST_INCOMPLETE
    /// (§8.1) rather than answered: handing a handler a short body it cannot distinguish from a whole one
    /// is a request-smuggling-shaped integrity fault (CWE-444), and a `200` for half an upload is worse
    /// than no answer at all.
    func serveHTTP3StreamingRequest(
        _ id: QUICStreamID,
        request inbound: HTTPRequest,
        buffered: (chunks: [[UInt8]], ended: Bool),
        stream: any QUICStream,
        engine: Engine,
        quic: any QUICConnection,
        registry: HTTP3StreamRegistry,
        deadlines: HTTP3StreamDeadlines<C.Instant>
    ) async {
        let handoff = AsyncHandoff()
        // The ingress seam (audit CR-F13) — the sanitized request is what the handler child captures.
        let (request, context) = RequestContext.ingress(inbound, over: quic)
        let current = currentSnapshot.responder  // hot-swappable responder, read once (G4a)
        let handler = Task {
            let response = await current.respond(
                to: request,
                body: .stream(HTTPRequestBodyStream(handoff: handoff)),
                context: context
            )
            await handoff.abandon()  // unblock the feeder if the handler returned without draining
            return response
        }
        var ended = buffered.ended
        for chunk in buffered.chunks {
            await handoff.offer(chunk)
        }
        // The body feed is a read loop of its own, so it carries the same idle bound (P0.5): a peer
        // that sends HEADERS and then stalls mid-upload no longer holds the stream open forever. The
        // watchdog resets the stream on a lapse, which is what unblocks the receive below.
        defer { deadlines.disarm(id) }
        armHTTP3(id, phase: .body, on: deadlines)
        while !ended, let chunk = try? await stream.receive() {
            deadlines.disarm(id)  // the read landed; handler time is not a read deadline
            let (produced, actions) = await engine.receive(id, chunk.bytes, fin: chunk.fin)
            await applyHTTP3(actions, registry: registry, engine: engine, quic: quic)
            for event in produced where Self.owningStream(of: event) == id {
                if case .requestBodyChunk(_, let bytes) = event {
                    await handoff.offer(bytes)
                }
                else if case .requestEnd = event {
                    ended = true
                }
            }
            if chunk.fin {
                break
            }
            armHTTP3(id, phase: .body, on: deadlines)
        }
        guard ended else {
            await abandonTruncatedHTTP3Request(
                id, handoff: handoff, handler: handler, stream: stream, registry: registry
            )
            return
        }
        await handoff.finish()
        let response = await handler.value
        await sendHTTP3Response(
            response,
            omitBody: request.method == .head,
            id: id,
            stream: stream,
            engine: engine,
            quic: quic,
            registry: registry
        )
        registry.retire(id)
    }

    /// Refuses a streaming request whose body never reached a valid end (RFC 9114 §8.1).
    ///
    /// The handoff is failed rather than finished, so the handler's body iteration ends *without* the
    /// clean end-of-body it would otherwise be told; the handler task is cancelled and awaited so it
    /// cannot outlive the stream, its response is discarded, and the stream is reset with
    /// H3_REQUEST_INCOMPLETE so the peer learns the request was not processed.
    private func abandonTruncatedHTTP3Request(
        _ id: QUICStreamID,
        handoff: AsyncHandoff,
        handler: Task<ServerResponse, Never>,
        stream: any QUICStream,
        registry: HTTP3StreamRegistry
    ) async {
        await handoff.fail()
        handler.cancel()
        _ = await handler.value
        stream.reset(errorCode: HTTP3ErrorCode.h3RequestIncomplete.rawValue)
        registry.retire(id)
    }

    /// Collects the body chunks (and whether `requestEnd` arrived) that follow a `requestHead` in the
    /// same event batch — handed to ``serveHTTP3StreamingRequest`` so a HEADERS+DATA+FIN that decoded
    /// together is not lost before the feed loop starts.
    static func trailingBody(
        of events: [HTTP3Connection.Event], after index: Int
    ) -> (chunks: [[UInt8]], ended: Bool) {
        var chunks: [[UInt8]] = []
        var ended = false
        for event in events[(index + 1)...] {
            if case .requestBodyChunk(_, let bytes) = event {
                chunks.append(bytes)
            }
            else if case .requestEnd = event {
                ended = true
            }
        }
        return (chunks, ended)
    }

    /// Streams a response natively on a QUIC request stream (RFC 9114 §4.1).
    ///
    /// The QPACK HEADERS frame goes first (`fin:false`), then each body chunk as a DATA frame as the
    /// producer yields it, then an empty FIN ends the stream; a HEAD request sends the headers with FIN
    /// and no body (RFC 9110 §9.3.2). QUIC streams are independent with transport-level backpressure
    /// (`stream.send` suspends until the transport accepts the bytes), so — unlike HTTP/2's shared,
    /// window-coupled connection — the producer drives the stream inline with no flow-control deadlock.
    /// A producer or transport fault mid-body resets the stream with H3_REQUEST_INCOMPLETE (§8.1) so the
    /// client sees a truncated response rather than a silently short one.
    func streamHTTP3Response(
        _ head: HTTPResponse,
        body: ResponseStream,
        omitBody: Bool,
        id: QUICStreamID,
        engine: Engine,
        on stream: any QUICStream
    ) async {
        guard let headerBytes = await engine.respondHeaders(to: id, head) else {
            stream.reset(errorCode: HTTP3ErrorCode.h3InternalError.rawValue)
            return
        }
        do {
            guard !omitBody else {
                // HEAD: the header section with FIN and no body (RFC 9110 §9.3.2).
                try await stream.send(headerBytes, fin: true)
                return
            }
            try await stream.send(headerBytes, fin: false)
            try await body.produce(H3StreamWriter(stream: stream))
            try await stream.send([], fin: true)  // end-of-body (RFC 9114 §4.1)
        }
        catch {
            stream.reset(errorCode: HTTP3ErrorCode.h3RequestIncomplete.rawValue)
        }
    }
    /// Writes HTTP/3 response-body chunks as DATA frames (RFC 9114 §7.2.1), one `send` per chunk so the
    /// QUIC stream's flow control is the backpressure point — no engine round-trip, since the body of an
    /// independent QUIC stream needs no connection state (RFC 9000 §2).
    private struct H3StreamWriter: ResponseBodyWriter {
        let stream: any QUICStream

        func write(_ chunk: [UInt8]) async throws {
            guard !chunk.isEmpty else {
                return
            }
            try await stream.send(HTTP3Connection.dataFrame(chunk), fin: false)
        }
    }
}
