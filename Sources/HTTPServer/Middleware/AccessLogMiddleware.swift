//
//  AccessLogMiddleware.swift
//  HTTPServer
//
//  A side-effecting, pass-through middleware: it records one access-log line per exchange and returns
//  the response untouched. The log sink is injected, so it stays testable and never assumes a logging
//  backend.
//

public import HTTPCore

/// Records one access-log line per request — `METHOD path -> status` — through an injected sink.
public struct AccessLogMiddleware: HTTPMiddleware {
    private let sink: @Sendable (String) -> Void

    /// Creates the middleware, sending each formatted line to `sink` (e.g. `{ print($0) }`).
    public init(_ sink: @escaping @Sendable (String) -> Void) {
        self.sink = sink
    }

    /// Delegates, then logs the method, path, and resulting status.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        let response = await next.respond(to: request, body: body)
        sink("\(request.method.rawValue) \(request.path) -> \(response.head.status.code)")
        return response
    }
}
