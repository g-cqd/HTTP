//
//  HTTPServer.swift
//  HTTPServer
//
//  The HTTP/1.1 server runtime: accepts connections from any transport backbone, fans them out
//  across cores with a task group, and serves each by streaming bytes through the sans-I/O HTTP/1.1
//  parser, invoking the responder, and serializing the reply.
//

internal import HTTP1
public import HTTPCore
public import HTTPTransport

/// An HTTP/1.1 server that drives an ``HTTPResponder`` over a ``ServerTransport``.
public final class HTTPServer: Sendable {

    private let transport: any ServerTransport
    private let responder: any HTTPResponder
    private let limits: HTTPLimits

    /// Creates a server bound to `transport`, handling requests with `responder`.
    public init(
        transport: any ServerTransport,
        responder: any HTTPResponder,
        limits: HTTPLimits = .default
    ) {
        self.transport = transport
        self.responder = responder
        self.limits = limits
    }

    /// Starts accepting connections and serves each concurrently until the transport finishes.
    public func run() async throws {
        let connections = try await transport.start()
        await withDiscardingTaskGroup { group in
            for await connection in connections {
                group.addTask { await self.serve(connection) }
            }
        }
    }

    /// Serves a connection for its lifetime: read → respond → write, looping while it stays
    /// persistent (RFC 9112 §9.3), then closes.
    func serve(_ connection: any TransportConnection) async {
        var buffer = [UInt8]()
        while await serveOne(connection, buffer: &buffer) {}
        await connection.close()
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
        let response = await responder.respond(to: request, body: framed.parsed.body)
        // A response to HEAD repeats the GET header section but sends no body (RFC 9112 §6.3).
        let bytes = ResponseSerializer.serialize(
            response.head, body: response.body, omitBody: request.method == .head)
        do {
            try await connection.send(bytes)
        } catch {
            return false
        }
        return !Self.shouldClose(request: request, response: response.head)
    }

    /// Reads from `connection`, accumulating into `buffer` until a complete request frames, EOF on a
    /// request boundary (graceful), or a parse error.
    private func readRequest(
        from connection: any TransportConnection,
        into buffer: inout [UInt8]
    ) async throws -> ReadOutcome {
        while true {
            switch parseStep(buffer) {
            case .complete(let parsed, let consumed):
                return .request(FramedRequest(parsed: parsed, consumed: consumed))
            case .incomplete:
                break  // need more bytes from the wire
            case .failed(let error):
                throw error
            }
            guard let chunk = try await connection.receive(maxLength: 16_384), !chunk.isEmpty else {
                // EOF: graceful on a request boundary, truncation mid-request.
                if buffer.isEmpty { return .cleanClose }
                throw HTTP1ParseError.incompleteHeaders
            }
            buffer.append(contentsOf: chunk)
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

    private enum ParseStep {
        case complete(ParsedRequest, consumed: Int)
        case incomplete
        case failed(HTTP1ParseError)
    }

    /// Attempts a parse over the borrowed buffer (zero-copy), distinguishing "need more data" from a
    /// genuine protocol error.
    ///
    /// The one-shot M2 parsers can only tell "malformed" from "truncated" once the header section is
    /// whole, so the server first frames at the end-of-headers marker (RFC 9112 §2.1, CRLF CRLF);
    /// until it arrives the request is simply incomplete. A short body then surfaces as
    /// ``HTTP1ParseError/incompleteBody``, which also means "read more".
    private func parseStep(_ buffer: [UInt8]) -> ParseStep {
        guard Self.headerSectionComplete(buffer) else { return .incomplete }
        let outcome: Result<FramedRequest, HTTP1ParseError> = buffer.withUnsafeBytes { raw in
            Result { () throws(HTTP1ParseError) in
                var reader = ByteReader(raw)
                let parsed = try RequestParser.parse(&reader, limits: limits)
                return FramedRequest(parsed: parsed, consumed: reader.position)
            }
        }
        switch outcome {
        case .success(let framed):
            return .complete(framed.parsed, consumed: framed.consumed)
        case .failure(.incompleteHeaders), .failure(.incompleteBody):
            return .incomplete
        case .failure(let error):
            return .failed(error)
        }
    }

    /// Whether `buffer` ends its header section.
    ///
    /// It contains the empty line CRLF CRLF that terminates the field block (RFC 9112 §2.1).
    /// Scanned iteratively (no recursion).
    private static func headerSectionComplete(_ buffer: [UInt8]) -> Bool {
        guard buffer.count >= 4 else { return false }
        var index = 3
        while index < buffer.count {
            if buffer[index] == 0x0A, buffer[index - 1] == 0x0D,
                buffer[index - 2] == 0x0A, buffer[index - 3] == 0x0D
            {
                return true
            }
            index += 1
        }
        return false
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
        default:
            .badRequest
        }
    }

    /// Whether the connection must close after this exchange.
    ///
    /// A `close` connection-option on either the request or the response ends persistence
    /// (RFC 9110 §7.6.1; RFC 9112 §9.6).
    private static func shouldClose(request: HTTPRequest, response: HTTPResponse) -> Bool {
        requestsClose(request.headerFields) || requestsClose(response.headerFields)
    }

    /// Whether `fields` carries the `close` connection-option within the comma-separated
    /// `Connection` list, matched case-insensitively (RFC 9110 §7.6.1).
    private static func requestsClose(_ fields: HTTPFields) -> Bool {
        guard let value = fields[.connection] else { return false }
        return value.split(separator: ",").contains { isCloseToken($0) }
    }

    private static func isCloseToken(_ option: Substring) -> Bool {
        option.lowercased().filter { $0 != " " && $0 != "\t" } == "close"
    }
}
