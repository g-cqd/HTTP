//
//  HTTPServer.swift
//  HTTPServer
//
//  The HTTP/1.1 server runtime: accepts connections from any transport backbone, fans them out
//  across cores with a task group, and serves each by streaming bytes through the sans-I/O HTTP/1.1
//  parser, invoking the responder, and serializing the reply.
//

internal import HTTP1
internal import HTTP2
public import HTTPCore
public import HTTPTransport
internal import Synchronization
public import WebSocket

/// An HTTP/1.1 · HTTP/2 server that drives an ``HTTPResponder`` over a ``ServerTransport``.
///
/// The server is generic over the `Clock` its Slowloris/idle deadlines are timed against. Production
/// uses the real ``ContinuousClock`` (via the convenience initializer); a test injects a
/// deterministic clock, so the timeout paths run with zero real-time waiting.
public final class HTTPServer<C: Clock>: Sendable where C.Duration == Duration {
    let transport: any ServerTransport
    /// An optional QUIC transport run alongside the TCP one to serve HTTP/3 (RFC 9114).
    let quicTransport: (any QUICServerTransport)?
    let responder: any HTTPResponder
    /// Handles connections that upgrade to WebSocket (RFC 6455 §4), or nil to refuse upgrades.
    let webSocketHandler: (any WebSocketHandler)?
    let limits: HTTPLimits
    let clock: C
    /// The `Alt-Svc` value advertising HTTP/3 (RFC 7838), set once the QUIC listener binds its port.
    let altSvc = Mutex<String?>(nil)

    /// Set once ``shutdown()`` begins a graceful drain.
    ///
    /// The per-connection serve loops read it to finish the current exchange and then close (HTTP/1
    /// with `Connection: close`, HTTP/2 with a GOAWAY, RFC 9113 §6.8) instead of awaiting another
    /// request. The drain helpers live in `HTTPServer+Shutdown.swift`.
    let isShuttingDown = Atomic<Bool>(false)

    /// Live connection counts: a global total (``HTTPLimits/maxConnections``) and a per-host map
    /// (``HTTPLimits/maxConnectionsPerClient``), guarded together.
    ///
    /// A `Mutex` (not an actor) because the critical section is a single map/counter update with no
    /// `await`.
    private let connectionCounts = Mutex<ConnectionCounts>(ConnectionCounts())

    /// In-flight connections being served, keyed by id, registered/unregistered around ``serve(_:)``.
    ///
    /// ``shutdown(within:)`` force-closes any that have not drained by the deadline.
    let activeConnections = Mutex<[TransportConnectionID: any TransportConnection]>([:])

    /// Live connection accounting: a global total plus per-host counts.
    private struct ConnectionCounts {
        var total = 0
        var perHost: [String: Int] = [:]
    }

    /// Creates a server bound to `transport`, handling requests with `responder` and timing its
    /// Slowloris/idle deadlines against `clock`.
    public init(
        transport: any ServerTransport,
        responder: any HTTPResponder,
        quicTransport: (any QUICServerTransport)? = nil,
        webSocketHandler: (any WebSocketHandler)? = nil,
        limits: HTTPLimits = .default,
        clock: C
    ) {
        self.transport = transport
        self.quicTransport = quicTransport
        self.responder = responder
        self.webSocketHandler = webSocketHandler
        self.limits = limits
        self.clock = clock
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Starts accepting connections and serves each concurrently until the transport finishes.
    ///
    /// When a ``QUICServerTransport`` was supplied it is run alongside the TCP listener to serve
    /// HTTP/3 (RFC 9114), and `Alt-Svc` (RFC 7838) is advertised on the h1/h2 responses.
    public func run() async throws {
        let connections = try await transport.start()
        await withDiscardingTaskGroup { group in
            if quicTransport != nil {
                group.addTask { await self.runHTTP3() }
            }
            for await connection in connections {
                group.addTask { await self.accept(connection) }
            }
        }
    }

    /// Admits `connection` if it is under both the global (``HTTPLimits/maxConnections``) and
    /// per-client (``HTTPLimits/maxConnectionsPerClient``) caps, serves it for its lifetime, then
    /// releases the slot.
    ///
    /// A connection over either cap is closed immediately — a resource-exhaustion defense (the spirit
    /// of a 429): the per-client cap (T-F4) blunts a single source, the global cap (audit T-F2) bounds
    /// total live connections so a many-source flood cannot exhaust file descriptors / tasks.
    private func accept(_ connection: any TransportConnection) async {
        let host = connection.peer.host
        let admitted = connectionCounts.withLock { counts in
            guard counts.total < limits.maxConnections else {
                return false
            }
            let current = counts.perHost[host, default: 0]
            guard current < limits.maxConnectionsPerClient else {
                return false
            }
            counts.perHost[host] = current + 1
            counts.total += 1
            return true
        }
        guard admitted else {
            await connection.close()
            return
        }
        await serve(connection)
        connectionCounts.withLock { counts in
            counts.total -= 1
            guard let current = counts.perHost[host] else {
                return
            }
            if current <= 1 {
                counts.perHost[host] = nil
            }
            else {
                counts.perHost[host] = current - 1
            }
        }
    }

    /// Serves a connection for its lifetime, dispatching by protocol, then closes.
    ///
    /// The first octets are sniffed: a connection that opens with the HTTP/2 client preface (h2c
    /// "prior knowledge", RFC 9113 §3.4) is driven by the HTTP/2 engine; anything else is HTTP/1.x.
    /// The distinctive prefix "PRI * HTTP/2.0\r\n" that no HTTP/1 request line can match; once it is
    /// seen the connection is committed to HTTP/2 even if the *full* preface then proves invalid (so
    /// the engine can answer with GOAWAY rather than mis-routing to HTTP/1).
    func serve(_ connection: any TransportConnection) async {
        activeConnections.withLock { $0[connection.id] = connection }
        defer { activeConnections.withLock { $0[connection.id] = nil } }
        // TLS ALPN (RFC 7301) settles the protocol before any byte is read: "h2" commits the
        // connection to HTTP/2 (RFC 9113 §3.3), so the engine — not the preface sniffer — drives it
        // (a malformed preface then earns a GOAWAY instead of mis-routing to HTTP/1.1). Any other
        // negotiated value, or cleartext (nil), falls through to the h2c/HTTP-1 sniff below.
        if connection.negotiatedApplicationProtocol == "h2" {
            await withIdleWatchdog(connection) { deadline in
                await self.serveHTTP2(connection, deadline: deadline, initialBytes: [])
            }
            await connection.close()
            return
        }

        await withIdleWatchdog(connection) { deadline in
            var buffer: [UInt8] = []
            // Read until the 16-octet marker is confirmed or the start diverges from it (HTTP/1.x).
            while buffer.count < Self.http2MarkerLength, Self.couldBeHTTP2Preface(buffer) {
                deadline.arm(self.clock.now.advanced(by: self.limits.keepAliveTimeout))
                let chunk = try? await connection.receive(maxLength: 16_384)
                deadline.disarm()
                guard let chunk, !chunk.isEmpty else { break }
                buffer.append(contentsOf: chunk)
            }

            if Self.matchesHTTP2Marker(buffer) {
                await self.serveHTTP2(connection, deadline: deadline, initialBytes: buffer)
            }
            else {
                while await self.serveOne(connection, deadline: deadline, buffer: &buffer) {
                    // Loop until serveOne returns false (close); the work is the call itself.
                }
            }
        }
        await connection.close()
    }

    /// Serves one request/response exchange.
    ///
    /// Returns `true` to keep the persistent connection open for a following request, `false` to
    /// close (a parse error, a `Connection: close`, EOF, or a transport failure).
    private func serveOne(
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
        let response = await responder.respond(to: request, body: framed.parsed.body)
        var head = withAltSvc(response.head)
        // Graceful shutdown: signal this is the last exchange (RFC 9110 §7.6.1) and close after it.
        let draining = applyHTTP1Drain(to: &head)
        // A response to HEAD repeats the GET header section but sends no body (RFC 9112 §6.3).
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

extension HTTPServer where C == ContinuousClock {
    /// Creates a server timing its deadlines against the real ``ContinuousClock`` — the production
    /// default.
    ///
    /// Inject a deterministic clock with the designated initializer in tests.
    public convenience init(
        transport: any ServerTransport,
        responder: any HTTPResponder,
        quicTransport: (any QUICServerTransport)? = nil,
        webSocketHandler: (any WebSocketHandler)? = nil,
        limits: HTTPLimits = .default
    ) {
        self.init(
            transport: transport,
            responder: responder,
            quicTransport: quicTransport,
            webSocketHandler: webSocketHandler,
            limits: limits,
            clock: ContinuousClock()
        )
    }
}
