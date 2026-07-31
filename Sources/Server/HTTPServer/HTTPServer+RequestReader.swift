//
//  HTTPServer+RequestReader.swift
//  HTTPServer
//
//  The HTTP/1.1 per-exchange pipeline, split out of HTTPServer.swift for navigability: serve one
//  request/response (`serveOne`), read toward a complete request bounding every phase against the
//  Slowloris/idle deadlines (`readRequest`), and assemble + frame the head and body (`assemble`,
//  `parseHeadStep`, `frameBody`, `headerSectionEnd`) with the small step types they thread. `serveOne`
//  is internal so the protocol sniffer in `serve` (main file) can drive the keep-alive loop; the rest
//  stay private here, and `BodyStep` stays internal so `HTTPServer+Chunked.swift` can produce it.
//  The streaming-route exchange lives in HTTPServer+RequestStreaming.swift, next to the body producer
//  it drives.
//

internal import HTTP1
internal import HTTPCore
internal import HTTPTransport
internal import WebSocket

extension HTTPServer where C.Duration == Duration {
    /// Serves one request/response exchange.
    ///
    /// Returns `true` to keep the persistent connection open for a following request, `false` to
    /// close (a parse error, a `Connection: close`, EOF, or a transport failure).
    func serveOne(
        _ connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        buffer: inout [UInt8],
        start: inout Int,
        responseBuffer: inout [UInt8]
    ) async -> Bool {
        reclaim(&buffer, start: &start)
        // ONE read of the hot-swappable table for this whole exchange (G4a / audit CR-F12): route
        // resolution, the body limit it yields, the WebSocket dispatch and the responder below all come
        // from this generation, so a `reloadResponder` landing mid-body cannot pair an old body limit
        // with a new handler.
        let snapshot = currentSnapshot
        let outcome: ReadOutcome
        do {
            outcome = try await readRequest(
                from: connection,
                deadline: deadline,
                into: &buffer,
                start: start,
                in: snapshot
            )
        }
        catch let error as HTTP1ParseError {
            await sendErrorResponse(for: error, to: connection)
            return false  // fail closed
        }
        catch {
            return false  // transport-level read failure
        }
        if case .streamingRequest(let pending) = outcome {
            // A streaming route (Phase 1.4): dispatch with an incremental body stream and read the body
            // off the wire into it; ``serveStreaming`` owns the cursor + response for this exchange.
            return await serveStreaming(
                connection,
                deadline: deadline,
                pending: pending,
                buffer: &buffer,
                start: &start,
                responseBuffer: &responseBuffer,
                in: snapshot
            )
        }
        guard case .request(let framed) = outcome else {
            return false  // clean EOF on a boundary
        }
        // Advance past this request (O(1)); any pipelined remainder stays in place, unshifted.
        start = framed.consumed

        // Build the per-request context from the verified connection metadata (peer, TLS subject, ALPN,
        // id) and take the sanitized request back. The verified mutual-TLS client identity (G3) reaches
        // handlers via `context.connection.tlsPeerSubject` rather than a header, and the same seam
        // strips every client-supplied server-asserted field off the request (audit CR-F13) — before
        // the WebSocket branch too, so a handshake handler cannot read a spoofed identity either.
        let (request, context) = RequestContext.ingress(framed.parsed.request, over: connection)
        // A WebSocket Upgrade request (RFC 6455 §4) to a matching `.webSocket` route the app accepts
        // hands the connection to the WebSocket engine for its lifetime; the h1 keep-alive loop ends
        // here. A non-upgrade GET to that path falls through to `respond` → 426 (the route's fallback);
        // a WebSocket path the responder does not declare resolves to `nil` and is served normally.
        if Self.isWebSocketUpgrade(request),
            let route = snapshot.resolver?.resolveWebSocket(path: request.path),
            let handler = route.webSocketHandler,
            handler.shouldUpgrade(request)
        {
            await serveWebSocket(
                connection,
                deadline: deadline,
                request: request,
                handler: handler,
                hub: route.webSocketHub,
                topic: route.webSocketTopic,
                carryover: Array(buffer[start...])
            )
            return false
        }
        let response = await snapshot.responder.respond(
            to: request, body: .collected(framed.parsed.body), context: context
        )
        var head = withAltSvc(response.head)
        // Graceful shutdown: signal this is the last exchange (RFC 9110 §7.6.1) and close after it.
        let draining = applyHTTP1Drain(to: &head)
        // A streamed body is pumped to the wire chunk by chunk (chunked transfer-coding); a buffered
        // body is serialized in one shot. A response to HEAD repeats the header section but sends no
        // body (RFC 9112 §6.3).
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
                version: framed.parsed.version, request: request, response: head
            )
        }
        // Serialize the head into the reused buffer; send it scatter-gather with the untouched body
        // buffer (one `writev`, no coalesce copy on the POSIX backbones — audit #4/L4). A HEAD or a
        // body-forbidden status (1xx/204/304) sends the head alone.
        let sendsBody = ResponseSerializer.serializeHead(
            head,
            bodyLength: response.body.count,
            omitBody: request.method == .head,
            into: &responseBuffer
        )
        // Bound the response send by the idle deadline (FIX #1): a slow-reading peer that fills the
        // socket send buffer would otherwise pin the serve task + connection slot forever (a Slowloris
        // slow-read). The buffered body is size-bounded (maxBody), so one idle-timeout window is the
        // right bound; a stalled send is reaped (the watchdog cancels this child task, unblocking the
        // send via the transport's per-call cancellation).
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
            return false  // finished this exchange while draining — close the connection
        }
        return !Self.shouldClose(
            version: framed.parsed.version, request: request, response: head
        )
    }

    /// Reclaims the keep-alive read buffer before the next request is read.
    ///
    /// First the consumed prefix (audit L3 — the keep-alive ring buffer): free the whole buffer when it
    /// is fully drained (the common non-pipelined case — O(1), storage kept), or shift out a large dead
    /// prefix so a pipelined stream cannot grow it without bound. Between pipelined requests we
    /// deliberately do *not* shift — advancing `start` is O(1), the win over a `removeFirst` memmove per
    /// request.
    ///
    /// Then the *storage*, which neither of those releases: `removeAll(keepingCapacity:)` and
    /// `removeFirst` both keep the array's buffer, by design. A buffered request body is accumulated
    /// here (`frameBody` needs the whole thing to build a `ParsedRequest`), so one large upload sizes
    /// this array to the upload — and keeping that peak hands it to every later request for as long as
    /// the peer holds the connection open, turning a one-off allocation into permanent per-connection
    /// residency. An idle keep-alive connection would sit on a gibibyte because it once carried one
    /// (audit CR-F5). So past the configured ceiling the storage is *released* and the few live octets
    /// are moved into a fresh array, which then grows back geometrically exactly as it did on this
    /// connection's first request. Deliberately not `reserveCapacity(ceiling)`: reserving speculates
    /// that the next request is large when it almost never is, and the allocator rounds the reservation
    /// up (65,536 becomes 81,888 here), so the ceiling would not actually be one.
    private func reclaim(_ buffer: inout [UInt8], start: inout Int) {
        if start == buffer.count {
            buffer.removeAll(keepingCapacity: true)
            start = 0
        }
        else if start >= 16_384 {
            buffer.removeFirst(start)
            start = 0
        }
        let ceiling = limits.keepAliveBufferCapacity
        // `count <= ceiling` is a second condition, not an assumption: a pipelined remainder larger
        // than the ceiling would only grow straight back, so leave it alone until it drains.
        guard buffer.capacity > ceiling, buffer.count <= ceiling else {
            return
        }
        var released: [UInt8] = []
        released.append(contentsOf: buffer)
        buffer = released
    }

    /// Caps an unterminated header section (431, throwing) and honors `Expect: 100-continue` once the
    /// head is parsed; returns `true` when the exchange must close (a 417 was sent).
    ///
    /// Extracted from ``readRequest`` to keep its loop within the complexity budget.
    private func handleIncomplete(
        _ buffer: [UInt8],
        start: Int,
        pending: PendingRequest?,
        expectHandled: inout Bool,
        on connection: any TransportConnection
    ) async throws -> Bool {
        // Until the head parses, the parser's size limits can't run (no CRLF CRLF yet), so a peer that
        // never terminates the header section would grow `buffer` unbounded. `pending == nil` ⇒ no
        // terminator ⇒ the unconsumed bytes are all header bytes: cap them and fail closed with 431
        // (RFC 9110 §15.5.13). `buffer.count - start` excludes any consumed pipelined prefix (L3).
        let headerBytes = buffer.count - start
        if pending == nil, headerBytes > limits.maxRequestLineLength + limits.maxHeaderListSize {
            throw HTTP1ParseError.headerSectionTooLarge
        }
        // Head parsed, body still arriving: honor `Expect` once before the (possibly waiting) peer sends
        // the body (RFC 9110 §10.1.1).
        if !expectHandled, let head = pending?.head {
            expectHandled = true
            return await handleExpect(head, on: connection)
        }
        return false
    }

    /// Reads from `connection`, accumulating into `buffer` until a complete request frames, EOF on a
    /// request boundary (graceful), a timeout (idle / Slowloris — fail closed), or a parse error.
    ///
    /// Each receive is bounded by a phase-appropriate limit from ``HTTPLimits``: the keep-alive
    /// timeout while idle between requests, a *cumulative* header-read deadline while the header
    /// section is still arriving (so a byte-at-a-time Slowloris cannot reset it), and the idle timeout
    /// while a body streams in (RFC 9112 §9.3; the limits are the defense-in-depth knobs).
    private func readRequest(
        from connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        into buffer: inout [UInt8],
        start: Int,
        in snapshot: ResponderSnapshot
    ) async throws -> ReadOutcome {
        var headerDeadline: C.Instant?
        // Resumable end-of-headers scan (keeps header framing O(n), not O(n²)); an absolute index into
        // `buffer`, so it begins at the request's start cursor, not 0 (audit L3 — keep-alive ring buffer).
        var scanOffset = start
        var pending: PendingRequest?  // the head, parsed once, then reused as the body arrives
        // Resumable chunked-body decode kept across reads — O(n), not O(n²) (audit H1-F1).
        var chunked = ChunkedProgress()
        var expectHandled = false  // honor `Expect: 100-continue` once, before the body is read
        // The matched route's body limit, resolved once when the head is parsed (Phase 1.2); `nil` ⇒ the
        // global ``HTTPLimits/maxBodySize``.
        var bodyLimit: Int?
        while true {
            switch assemble(
                buffer,
                start: start,
                scanOffset: &scanOffset,
                pending: &pending,
                chunked: &chunked,
                bodyLimit: &bodyLimit,
                in: snapshot
            ) {
                case .request(let framed):
                    return .request(framed)
                case .streamingHead(let pending):
                    // A streaming route: stop framing here and hand the head to ``serveStreaming``, which
                    // reads the body incrementally into the request stream (RFC 9112 §7 — Phase 1.4).
                    return .streamingRequest(pending)
                case .incomplete:
                    if try await handleIncomplete(
                        buffer,
                        start: start,
                        pending: pending,
                        expectHandled: &expectHandled,
                        on: connection
                    ) {
                        // header section too large was thrown, or a 417 was sent
                        return .cleanClose
                    }
                case .failed(let error):
                    throw error
            }
            deadline.arm(
                clock.now.advanced(
                    by: receiveTimeout(buffer, headersParsed: pending != nil, &headerDeadline)
                )
            )
            let received: Int
            do {
                // Reads straight into the backbone's reused scratch and appends only the received bytes to
                // `buffer` — no fresh per-read chunk allocation (audit P1).
                received = try await connection.receive(into: &buffer, maxLength: 16_384)
            }
            catch {
                deadline.disarm()
                // The watchdog closed the connection (idle / Slowloris), or a genuine transport fault.
                if deadline.hasLapsed {
                    return .cleanClose
                }
                throw error
            }
            deadline.disarm()
            if deadline.hasLapsed {
                return .cleanClose  // timeout (the close surfaced as EOF)
            }
            guard received > 0 else {
                // EOF: graceful on a request boundary (nothing buffered for this request — the cursor
                // is at the tail), truncation mid-request otherwise.
                if start == buffer.count {
                    return .cleanClose
                }
                throw HTTP1ParseError.incompleteHeaders
            }
        }
    }

    /// Tries to assemble a complete request from `buffer`: parse the head exactly once (caching it in
    /// `pending`), then frame the body against it.
    ///
    /// Returns `.incomplete` when more bytes are needed.
    private func assemble(
        _ buffer: [UInt8],
        start: Int,
        scanOffset: inout Int,
        pending: inout PendingRequest?,
        chunked: inout ChunkedProgress,
        bodyLimit: inout Int?,
        in snapshot: ResponderSnapshot
    ) -> AssembleStep {
        if pending == nil {
            guard Self.headerSectionEnd(buffer, start: start, from: &scanOffset) != nil else {
                return .incomplete
            }
            switch parseHeadStep(buffer, start: start) {
                case .parsed(let parsed):
                    // Resolve the matched route at the head (Phase 1.2/1.4): reject an over-limit
                    // Content-Length before buffering, cap a chunked body to the route limit during
                    // framing, and hand a streaming route's body off incrementally (`.streamingHead`).
                    // The size policy runs HERE — after resolution, matching h2/h3's resolveBodyLimit
                    // flow — so a route cap REPLACES the global bound (it may raise as well as
                    // tighten); the parser resolves framing with no size policy of its own. `nil`
                    // (no router / no per-route cap) falls back to the global maxBodySize.
                    let resolved = snapshot.resolver?
                        .resolve(
                            method: parsed.head.request.method, path: parsed.head.request.path
                        )
                    bodyLimit = resolved?.bodyLimit
                    let effectiveLimit = resolved?.bodyLimit ?? limits.maxBodySize
                    if case .contentLength(let length) = parsed.head.framing,
                        length > effectiveLimit
                    {
                        return .failed(.bodyTooLarge)
                    }
                    if resolved?.streamsBody == true {
                        return .streamingHead(parsed)
                    }
                    pending = parsed
                case .failed(let error):
                    return .failed(error)
            }
        }
        guard let pending else {
            return .incomplete
        }
        switch frameBody(buffer, pending, chunked: &chunked, bodyLimit: bodyLimit) {
            case .complete(let parsed, let consumed):
                return .request(FramedRequest(parsed: parsed, consumed: consumed))
            case .incomplete:
                return .incomplete
            case .failed(let error):
                return .failed(error)
        }
    }

    /// One framed request plus the byte count it consumed (so a pipelined remainder survives).
    private struct FramedRequest {
        let parsed: ParsedRequest
        let consumed: Int
    }

    /// The result of reading toward one request: a fully-framed request, a streaming route's parsed head
    /// (its body read incrementally by ``serveStreaming``), or a graceful close.
    private enum ReadOutcome {
        case request(FramedRequest)
        case streamingRequest(PendingRequest)
        case cleanClose
    }

    /// A request head parsed once, retained while its body is framed across reads.
    struct PendingRequest {
        let head: RequestHead
        /// Absolute index in the read buffer where this request's body begins (just past its header
        /// section) — the cursor start plus the head's length, so framing works on a pipelined remainder.
        let bodyStart: Int
    }

    private enum AssembleStep {
        case request(FramedRequest)
        case streamingHead(PendingRequest)
        case incomplete
        case failed(HTTP1ParseError)
    }

    private enum HeadStep {
        case parsed(PendingRequest)
        case failed(HTTP1ParseError)
    }

    // Internal (not private) so the chunked framing in HTTPServer+Chunked.swift can produce it.
    enum BodyStep {
        case complete(ParsedRequest, consumed: Int)
        case incomplete
        case failed(HTTP1ParseError)
    }

    /// The index just past the header section's terminating CRLF CRLF (RFC 9112 §2.1), or nil if it
    /// has not arrived.
    ///
    /// Resumes scanning from `offset`, re-checking the last three octets so a terminator split across
    /// reads is not missed; this keeps the total header scan O(n) rather than O(n²) over many chunks.
    private static func headerSectionEnd(
        _ buffer: [UInt8], start: Int, from offset: inout Int
    ) -> Int? {
        var index = max(offset, start + 3)
        while index < buffer.count {
            if buffer[index] == 0x0A, buffer[index - 1] == 0x0D,
                buffer[index - 2] == 0x0A, buffer[index - 3] == 0x0D
            {
                return index + 1
            }
            index += 1
        }
        // Resume near the tail next time so a CRLF CRLF split across reads is still matched.
        offset = max(start + 3, buffer.count - 3)
        return nil
    }

    /// Parses the request head over the borrowed buffer (zero-copy), once the header section is whole.
    ///
    /// The caller invokes this only after ``headerSectionEnd(_:from:)`` confirms the CRLF CRLF
    /// terminator, so a failure here is a genuine malformed-head error, never "need more bytes".
    private func parseHeadStep(_ buffer: [UInt8], start: Int) -> HeadStep {
        let outcome: Result<PendingRequest, HTTP1ParseError> = buffer.withUnsafeBytes { raw in
            Result { () throws(HTTP1ParseError) in
                // Parse from the request's start cursor (a zero-copy rebase), not buffer index 0, so a
                // pipelined remainder left in place still parses correctly (audit L3).
                var reader = ByteReader(UnsafeRawBufferPointer(rebasing: raw[start...]))
                let head = try RequestParser.parseHead(&reader, limits: limits)
                return PendingRequest(head: head, bodyStart: start + reader.position)
            }
        }
        switch outcome {
            case .success(let pending):
                return .parsed(pending)
            case .failure(let error):
                return .failed(error)
        }
    }

    /// Frames the body against the already-parsed head, without re-parsing the head (RFC 9112 §6).
    private func frameBody(
        _ buffer: [UInt8],
        _ pending: PendingRequest,
        chunked: inout ChunkedProgress,
        bodyLimit: Int?
    ) -> BodyStep {
        let head = pending.head
        let start = pending.bodyStart
        switch head.framing {
            case .none:
                return .complete(
                    ParsedRequest(request: head.request, body: [], version: head.version),
                    consumed: start
                )
            case .contentLength(let length):
                guard buffer.count - start >= length else {
                    return .incomplete
                }
                let body = Array(buffer[start ..< (start + length)])
                return .complete(
                    ParsedRequest(request: head.request, body: body, version: head.version),
                    consumed: start + length
                )
            case .chunked:
                return frameChunkedBody(
                    buffer, head: head, start: start, chunked: &chunked, bodyLimit: bodyLimit
                )
        }
    }
}
