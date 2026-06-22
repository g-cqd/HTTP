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

    private let transport: any ServerTransport
    private let responder: any HTTPResponder
    /// Handles connections that upgrade to WebSocket (RFC 6455 §4), or nil to refuse upgrades.
    let webSocketHandler: (any WebSocketHandler)?
    let limits: HTTPLimits
    private let clock: C

    /// Live connection counts: a global total (``HTTPLimits/maxConnections``) and a per-host map
    /// (``HTTPLimits/maxConnectionsPerClient``), guarded together.
    ///
    /// A `Mutex` (not an actor) because the critical section is a single map/counter update with no
    /// `await`.
    private let connectionCounts = Mutex<ConnectionCounts>(ConnectionCounts())

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
        webSocketHandler: (any WebSocketHandler)? = nil,
        limits: HTTPLimits = .default,
        clock: C
    ) {
        self.transport = transport
        self.responder = responder
        self.webSocketHandler = webSocketHandler
        self.limits = limits
        self.clock = clock
    }

    /// Starts accepting connections and serves each concurrently until the transport finishes.
    public func run() async throws {
        let connections = try await transport.start()
        await withDiscardingTaskGroup { group in
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
            guard counts.total < limits.maxConnections else { return false }
            let current = counts.perHost[host, default: 0]
            guard current < limits.maxConnectionsPerClient else { return false }
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
            guard let current = counts.perHost[host] else { return }
            if current <= 1 {
                counts.perHost[host] = nil
            } else {
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
    private static var http2MarkerLength: Int { 16 }

    func serve(_ connection: any TransportConnection) async {
        // TLS ALPN (RFC 7301) settles the protocol before any byte is read: "h2" commits the
        // connection to HTTP/2 (RFC 9113 §3.3), so the engine — not the preface sniffer — drives it
        // (a malformed preface then earns a GOAWAY instead of mis-routing to HTTP/1.1). Any other
        // negotiated value, or cleartext (nil), falls through to the h2c/HTTP-1 sniff below.
        if connection.negotiatedApplicationProtocol == "h2" {
            await serveHTTP2(connection, initialBytes: [])
            await connection.close()
            return
        }

        var buffer = [UInt8]()
        // Read until the 16-octet marker is confirmed or the start diverges from it (HTTP/1.x).
        while buffer.count < Self.http2MarkerLength, Self.couldBeHTTP2Preface(buffer) {
            guard
                let chunk = try? await withTimeout(
                    limits.keepAliveTimeout, { try await connection.receive(maxLength: 16_384) }),
                !chunk.isEmpty
            else { break }
            buffer.append(contentsOf: chunk)
        }

        if Self.matchesHTTP2Marker(buffer) {
            await serveHTTP2(connection, initialBytes: buffer)
        } else {
            while await serveOne(connection, buffer: &buffer) {}
        }
        await connection.close()
    }

    /// Whether `buffer` is a prefix of the HTTP/2 client preface (so the connection may still be h2).
    private static func couldBeHTTP2Preface(_ buffer: [UInt8]) -> Bool {
        let marker = HTTP2ConnectionPreface.client
        for index in 0..<min(buffer.count, marker.count) where buffer[index] != marker[index] {
            return false
        }
        return true
    }

    /// Whether the first 16 octets of `buffer` are the HTTP/2 preface marker (the commit point to h2).
    private static func matchesHTTP2Marker(_ buffer: [UInt8]) -> Bool {
        let marker = HTTP2ConnectionPreface.client
        guard buffer.count >= http2MarkerLength else { return false }
        for index in 0..<http2MarkerLength where buffer[index] != marker[index] { return false }
        return true
    }

    /// Drives the sans-I/O ``HTTP2Connection`` over `connection`: feed octets → events → respond →
    /// flush, looping until EOF, a timeout, or a connection-level protocol error.
    private func serveHTTP2(_ connection: any TransportConnection, initialBytes: [UInt8]) async {
        // Advertise Extended CONNECT (RFC 8441 §3) only when a WebSocket handler can service it.
        var settings = HTTP2Settings()
        settings.enableConnectProtocol = webSocketHandler != nil
        var engine = HTTP2Connection(localSettings: settings, limits: limits)
        // Per-stream WebSocket engines for active WebSocket-over-HTTP/2 tunnels (RFC 8441).
        var webSockets: [HTTP2StreamID: WebSocketConnection] = [:]
        var inbound = initialBytes
        while true {
            let events: [HTTP2Connection.Event]
            do {
                events = try engine.receive(inbound)
            } catch {
                // Connection-level protocol error: the engine queued a GOAWAY (RFC 9113 §6.8) — send
                // it best-effort so the peer learns the cause, then close.
                let goAway = engine.outboundBytes()
                if !goAway.isEmpty { try? await connection.send(goAway) }
                break
            }
            inbound = []
            for event in events {
                if case .request(let streamID, let request, let body) = event {
                    let response = await responder.respond(to: request, body: body)
                    do {
                        try engine.respond(to: streamID, response.head, body: response.body)
                    } catch {
                        // A connection-level fault (e.g. responding to an unknown stream) is fatal:
                        // flush the engine's queued GOAWAY (RFC 9113 §6.8) and close. A stream-level
                        // fault is contained — the engine queued RST_STREAM, flushed with this batch
                        // below — so other streams keep being served.
                        if error.isConnectionError {
                            let goAway = engine.outboundBytes()
                            if !goAway.isEmpty { try? await connection.send(goAway) }
                            return
                        }
                    }
                } else {
                    await handleHTTP2Tunnel(event, engine: &engine, webSockets: &webSockets)
                }
            }
            let outbound = engine.outboundBytes()
            if !outbound.isEmpty {
                do { try await connection.send(outbound) } catch { break }
            }
            guard
                let chunk = try? await withTimeout(
                    limits.idleTimeout, { try await connection.receive(maxLength: 16_384) }),
                !chunk.isEmpty
            else { break }
            inbound = chunk
        }
    }

    /// Serves one request/response exchange.
    ///
    /// Returns `true` to keep the persistent connection open for a following request, `false` to
    /// close (a parse error, a `Connection: close`, EOF, or a transport failure).
    private func serveOne(
        _ connection: any TransportConnection,
        buffer: inout [UInt8]
    ) async -> Bool {
        let outcome: ReadOutcome
        do {
            outcome = try await readRequest(from: connection, into: &buffer)
        } catch let error as HTTP1ParseError {
            await sendErrorResponse(for: error, to: connection)
            return false  // fail closed
        } catch {
            return false  // transport-level read failure
        }
        guard case .request(let framed) = outcome else { return false }  // clean EOF on a boundary
        buffer.removeFirst(framed.consumed)  // carry any pipelined remainder to the next iteration

        let request = framed.parsed.request
        // A WebSocket Upgrade request (RFC 6455 §4) the app accepts hands the connection to the
        // WebSocket engine for its lifetime; the h1 keep-alive loop ends here.
        if let handler = webSocketHandler, Self.isWebSocketUpgrade(request),
            handler.shouldUpgrade(request)
        {
            await serveWebSocket(connection, request: request, handler: handler, carryover: buffer)
            return false
        }
        let response = await responder.respond(to: request, body: framed.parsed.body)
        // A response to HEAD repeats the GET header section but sends no body (RFC 9112 §6.3).
        let bytes = ResponseSerializer.serialize(
            response.head, body: response.body, omitBody: request.method == .head)
        do {
            try await connection.send(bytes)
        } catch {
            return false
        }
        return !Self.shouldClose(
            version: framed.parsed.version, request: request, response: response.head)
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
        into buffer: inout [UInt8]
    ) async throws -> ReadOutcome {
        var headerDeadline: C.Instant?
        var scanOffset = 0  // resumable end-of-headers scan (keeps header framing O(n), not O(n²))
        var pending: PendingRequest?  // the head, parsed once, then reused as the body arrives
        // Resumable chunked-body decode kept across reads — O(n), not O(n²) (audit H1-F1).
        var chunked = ChunkedProgress()
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
            case .failed(let error):
                throw error
            }
            let chunk: [UInt8]?
            do {
                chunk = try await withTimeout(
                    receiveTimeout(buffer, headersParsed: pending != nil, &headerDeadline)
                ) {
                    try await connection.receive(maxLength: 16_384)
                }
            } catch is TimeoutError {
                return .cleanClose  // idle or slow-request timeout — close (Slowloris defense)
            }
            guard let chunk, !chunk.isEmpty else {
                // EOF: graceful on a request boundary, truncation mid-request.
                if buffer.isEmpty { return .cleanClose }
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
            case .parsed(let head): pending = head
            case .failed(let error): return .failed(error)
            }
        }
        guard let pending else { return .incomplete }
        switch frameBody(buffer, pending, chunked: &chunked) {
        case .complete(let parsed, let consumed):
            return .request(FramedRequest(parsed: parsed, consumed: consumed))
        case .incomplete:
            return .incomplete
        case .failed(let error):
            return .failed(error)
        }
    }

    /// The deadline for the next receive, chosen by request phase (the ``HTTPLimits`` Slowloris knobs).
    private func receiveTimeout(
        _ buffer: [UInt8],
        headersParsed: Bool,
        _ headerDeadline: inout C.Instant?
    ) -> Duration {
        if buffer.isEmpty { return limits.keepAliveTimeout }  // idle, awaiting the next request
        if headersParsed { return limits.idleTimeout }  // body phase
        let deadline = headerDeadline ?? clock.now.advanced(by: limits.headerReadTimeout)
        headerDeadline = deadline  // cumulative across the whole header section
        return max(.zero, clock.now.duration(to: deadline))
    }

    /// A sentinel for an operation that exceeded its deadline.
    private struct TimeoutError: Error {}

    /// Runs `operation`, cancelling it and throwing ``TimeoutError`` if it outlasts `duration`.
    ///
    /// The cancellation propagates to the connection's read (which honors it — closing the descriptor
    /// to unblock a stalled syscall), so a stalled peer cannot pin the task past the deadline.
    func withTimeout<Value: Sendable>(
        _ duration: Duration,
        _ operation: @escaping @Sendable () async throws -> Value
    ) async throws -> Value {
        let clock = self.clock
        return try await withThrowingTaskGroup(of: Value.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await clock.sleep(for: duration)
                throw TimeoutError()
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else { throw TimeoutError() }
            return result
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
        case .success(let pending): return .parsed(pending)
        case .failure(let error): return .failed(error)
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
                consumed: start)
        case .contentLength(let length):
            guard buffer.count - start >= length else { return .incomplete }
            let body = Array(buffer[start..<(start + length)])
            return .complete(
                ParsedRequest(request: head.request, body: body, version: head.version),
                consumed: start + length)
        case .chunked:
            return frameChunkedBody(buffer, head: head, start: start, chunked: &chunked)
        }
    }

    private func sendErrorResponse(
        for error: HTTP1ParseError,
        to connection: any TransportConnection
    ) async {
        var response = HTTPResponse(status: Self.status(for: error))
        // The server fails closed on a parse error, so it tells the peer (RFC 9112 §9.6).
        response.headerFields.append("close", for: .connection)
        let bytes = ResponseSerializer.serialize(response)
        try? await connection.send(bytes)
    }

    /// Maps a parse error to the response status it should produce (RFC 9110 §15).
    private static func status(for error: HTTP1ParseError) -> HTTPStatus {
        switch error {
        case .requestLineTooLong:
            .uriTooLong
        case .fieldTooLarge, .headerSectionTooLarge, .tooManyFields:
            .requestHeaderFieldsTooLarge
        case .bodyTooLarge:
            .contentTooLarge
        case .unsupportedVersion:
            .httpVersionNotSupported
        case .unsupportedTransferEncoding:
            // A transfer coding the server doesn't understand (RFC 9112 §6.1; audit H1-F5).
            .notImplemented
        default:
            .badRequest
        }
    }

    /// Whether the connection must close after this exchange.
    ///
    /// An explicit `close` connection-option on either message always ends persistence (RFC 9110
    /// §7.6.1). Otherwise the default follows the request version (RFC 9112 §9.3): HTTP/1.1 persists,
    /// while HTTP/1.0 closes unless the request asked to `keep-alive`.
    private static func shouldClose(
        version: HTTPVersion,
        request: HTTPRequest,
        response: HTTPResponse
    ) -> Bool {
        if connectionContains(request.headerFields, "close")
            || connectionContains(response.headerFields, "close")
        {
            return true
        }
        if version.major == 1, version.minor >= 1 { return false }
        return !connectionContains(request.headerFields, "keep-alive")
    }

    /// Whether the `Connection` field's comma-separated list contains `option` (case-insensitive,
    /// OWS-trimmed) — RFC 9110 §7.6.1.
    private static func connectionContains(_ fields: HTTPFields, _ option: String) -> Bool {
        guard let value = fields[.connection] else { return false }
        return value.split(separator: ",").contains { normalizedToken($0) == option }
    }

    private static func normalizedToken(_ option: Substring) -> String {
        option.lowercased().filter { $0 != " " && $0 != "\t" }
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
        webSocketHandler: (any WebSocketHandler)? = nil,
        limits: HTTPLimits = .default
    ) {
        self.init(
            transport: transport, responder: responder, webSocketHandler: webSocketHandler,
            limits: limits, clock: ContinuousClock())
    }
}
