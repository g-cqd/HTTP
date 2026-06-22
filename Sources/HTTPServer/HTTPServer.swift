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

    /// Serves a single connection: read a request, respond, write, close.
    func serve(_ connection: any TransportConnection) async {
        var buffer = [UInt8]()
        do {
            let parsed = try await readRequest(from: connection, into: &buffer)
            let response = await responder.respond(to: parsed.request, body: parsed.body)
            let bytes = ResponseSerializer.serialize(response.head, body: response.body)
            try await connection.send(bytes)
        } catch let error as HTTP1ParseError {
            await sendErrorResponse(for: error, to: connection)
        } catch {
            // Transport-level failure — nothing to send; fall through to close.
        }
        await connection.close()
    }

    /// Reads from `connection`, accumulating into `buffer` until a complete request parses.
    private func readRequest(
        from connection: any TransportConnection,
        into buffer: inout [UInt8]
    ) async throws -> ParsedRequest {
        while true {
            switch parseStep(buffer) {
            case .complete(let request):
                return request
            case .incomplete:
                break  // need more bytes from the wire
            case .failed(let error):
                throw error
            }
            guard let chunk = try await connection.receive(maxLength: 16_384), !chunk.isEmpty else {
                throw HTTP1ParseError.incompleteHeaders  // peer closed mid-request
            }
            buffer.append(contentsOf: chunk)
        }
    }

    private enum ParseStep {
        case complete(ParsedRequest)
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
        let outcome: Result<ParsedRequest, HTTP1ParseError> = buffer.withUnsafeBytes { raw in
            Result { () throws(HTTP1ParseError) in
                var reader = ByteReader(raw)
                return try RequestParser.parse(&reader, limits: limits)
            }
        }
        switch outcome {
        case .success(let request):
            return .complete(request)
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
        let bytes = ResponseSerializer.serialize(HTTPResponse(status: Self.status(for: error)))
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
}
