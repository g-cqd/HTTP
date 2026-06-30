//
//  ThrowingResponder.swift
//  HTTPServer
//
//  The error-mapping adapter for the (non-throwing) responder seam: wraps a `throws` handler and maps a
//  thrown ``HTTPError`` to its `application/problem+json` response (RFC 9457), and any other thrown
//  error to a generic `500` problem. This is how a handler `throw`s a typed error and has it rendered
//  without the core ``HTTPResponder`` requirement itself being throwing — the seam stays non-throwing,
//  the ergonomics are opt-in. A non-`HTTPError` is deliberately rendered as a bare `500` with no
//  `detail`, so an internal error's message is never leaked to the client.
//

public import HTTPCore

/// An ``HTTPResponder`` backed by a `throws` handler, mapping thrown errors to problem responses.
public struct ThrowingResponder: HTTPResponder {
    private let handler:
        @Sendable (HTTPRequest, RequestBody, RequestContext) async throws -> ServerResponse

    /// Creates a responder from a throwing request handler.
    ///
    /// A thrown ``HTTPError`` becomes its ``ServerResponse/problem(_:)`` response; any other error
    /// becomes a generic `500 Internal Server Error` problem with no detail.
    public init(
        _ handler:
            @escaping @Sendable (HTTPRequest, RequestBody, RequestContext) async throws ->
            ServerResponse
    ) {
        self.handler = handler
    }

    /// Runs the handler, mapping a thrown error to an `application/problem+json` response.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext
    ) async -> ServerResponse {
        do {
            return try await handler(request, body, context)
        }
        catch let error as HTTPError {
            return .problem(error)
        }
        catch {
            return .problem(status: .internalServerError, title: "Internal Server Error")
        }
    }
}
