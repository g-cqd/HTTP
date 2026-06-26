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
        buffer: inout [UInt8]
    ) async -> Bool {
        let outcome: ReadOutcome
        do {
            outcome = try await readRequest(from: connection, deadline: deadline, into: &buffer)
        }
        catch let error as HTTP1ParseError {
            await sendErrorResponse(for: error, to: connection)
            return false  // fail closed
        }
        catch {
            return false  // transport-level read failure
        }
        guard case .request(let framed) = outcome else {
            return false  // clean EOF on a boundary
        }
        buffer.removeFirst(framed.consumed)  // carry any pipelined remainder to the next iteration

        let request = framed.parsed.request
        // A WebSocket Upgrade request (RFC 6455 §4) the app accepts hands the connection to the
        // WebSocket engine for its lifetime; the h1 keep-alive loop ends here.
        if let handler = webSocketHandler, Self.isWebSocketUpgrade(request),
            handler.shouldUpgrade(request)
        {
            await serveWebSocket(
                connection,
                deadline: deadline,
                request: request,
                handler: handler,
                carryover: buffer
            )
            return false
        }
        // Surface the verified mutual-TLS client identity (G3) as a server-asserted header before the
        // responder runs — stripping any inbound spoof — so handlers/middleware can authorize on it.
        let stamped = Self.stampingClientCertSubject(request, from: connection)
        let response = await responder.respond(to: stamped, body: framed.parsed.body)
        var head = withAltSvc(response.head)
        // Graceful shutdown: signal this is the last exchange (RFC 9110 §7.6.1) and close after it.
        let draining = applyHTTP1Drain(to: &head)
        // A streamed body is pumped to the wire chunk by chunk (chunked transfer-coding); a buffered
        // body is serialized in one shot. A response to HEAD repeats the header section but sends no
        // body (RFC 9112 §6.3).
        if let stream = response.stream {
            let sent = await sendStreamedResponse(
                head, stream: stream, omitBody: request.method == .head, on: connection
            )
            guard sent, !draining else {
                return false
            }
            return !Self.shouldClose(
                version: framed.parsed.version, request: request, response: head
            )
        }
        let bytes = ResponseSerializer.serialize(
            head, body: response.body, omitBody: request.method == .head
        )
        do {
            try await connection.send(bytes)
        }
        catch {
            return false
        }
        if draining {
            return false  // finished this exchange while draining — close the connection
        }
        return !Self.shouldClose(
            version: framed.parsed.version, request: request, response: head
        )
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
        into buffer: inout [UInt8]
    ) async throws -> ReadOutcome {
        var headerDeadline: C.Instant?
        var scanOffset = 0  // resumable end-of-headers scan (keeps header framing O(n), not O(n²))
        var pending: PendingRequest?  // the head, parsed once, then reused as the body arrives
        // Resumable chunked-body decode kept across reads — O(n), not O(n²) (audit H1-F1).
        var chunked = ChunkedProgress()
        var expectHandled = false  // honor `Expect: 100-continue` once, before the body is read
        while true {
            switch assemble(buffer, scanOffset: &scanOffset, pending: &pending, chunked: &chunked) {
                case .request(let framed):
                    return .request(framed)
                case .incomplete:
                    // Until the head parses, the parser's size limits can't run (no CRLF CRLF yet), so a
                    // peer that never terminates the header section would grow `buffer` unbounded.
                    // `pending == nil` ⇒ no terminator present ⇒ the buffer is all header bytes: cap it
                    // and fail closed with 431 instead of exhausting memory (RFC 9110 §15.5.13).
                    if pending == nil,
                        buffer.count > limits.maxRequestLineLength + limits.maxHeaderListSize
                    {
                        throw HTTP1ParseError.headerSectionTooLarge
                    }
                    // Head parsed, body still arriving: honor `Expect` once before the (possibly
                    // waiting) peer sends the body (RFC 9110 §10.1.1).
                    if !expectHandled, let head = pending?.head {
                        expectHandled = true
                        if await handleExpect(head, on: connection) {
                            return .cleanClose  // a 417 was sent — the expectation cannot be met
                        }
                    }
                case .failed(let error):
                    throw error
            }
            deadline.arm(
                clock.now.advanced(
                    by: receiveTimeout(buffer, headersParsed: pending != nil, &headerDeadline)
                )
            )
            let chunk: [UInt8]?
            do {
                chunk = try await connection.receive(maxLength: 16_384)
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
            guard let chunk, !chunk.isEmpty else {
                // EOF: graceful on a request boundary, truncation mid-request.
                if buffer.isEmpty {
                    return .cleanClose
                }
                throw HTTP1ParseError.incompleteHeaders
            }
            buffer.append(contentsOf: chunk)
        }
    }

    /// Tries to assemble a complete request from `buffer`: parse the head exactly once (caching it in
    /// `pending`), then frame the body against it.
    ///
    /// Returns `.incomplete` when more bytes are needed.
    private func assemble(
        _ buffer: [UInt8],
        scanOffset: inout Int,
        pending: inout PendingRequest?,
        chunked: inout ChunkedProgress
    ) -> AssembleStep {
        if pending == nil {
            guard Self.headerSectionEnd(buffer, from: &scanOffset) != nil else {
                return .incomplete
            }
            switch parseHeadStep(buffer) {
                case .parsed(let head):
                    pending = head
                case .failed(let error):
                    return .failed(error)
            }
        }
        guard let pending else {
            return .incomplete
        }
        switch frameBody(buffer, pending, chunked: &chunked) {
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

    /// The result of reading toward one request: a framed request, or a graceful close.
    private enum ReadOutcome {
        case request(FramedRequest)
        case cleanClose
    }

    /// A request head parsed once, retained while its body is framed across reads.
    private struct PendingRequest {
        let head: RequestHead
        let headerLength: Int
    }

    private enum AssembleStep {
        case request(FramedRequest)
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
    private static func headerSectionEnd(_ buffer: [UInt8], from offset: inout Int) -> Int? {
        var index = max(offset, 3)
        while index < buffer.count {
            if buffer[index] == 0x0A, buffer[index - 1] == 0x0D,
                buffer[index - 2] == 0x0A, buffer[index - 3] == 0x0D
            {
                return index + 1
            }
            index += 1
        }
        // Resume near the tail next time so a CRLF CRLF split across reads is still matched.
        offset = max(3, buffer.count - 3)
        return nil
    }

    /// Parses the request head over the borrowed buffer (zero-copy), once the header section is whole.
    ///
    /// The caller invokes this only after ``headerSectionEnd(_:from:)`` confirms the CRLF CRLF
    /// terminator, so a failure here is a genuine malformed-head error, never "need more bytes".
    private func parseHeadStep(_ buffer: [UInt8]) -> HeadStep {
        let outcome: Result<PendingRequest, HTTP1ParseError> = buffer.withUnsafeBytes { raw in
            Result { () throws(HTTP1ParseError) in
                var reader = ByteReader(raw)
                let head = try RequestParser.parseHead(&reader, limits: limits)
                return PendingRequest(head: head, headerLength: reader.position)
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
        _ buffer: [UInt8], _ pending: PendingRequest, chunked: inout ChunkedProgress
    ) -> BodyStep {
        let head = pending.head
        let start = pending.headerLength
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
                return frameChunkedBody(buffer, head: head, start: start, chunked: &chunked)
        }
    }
}
