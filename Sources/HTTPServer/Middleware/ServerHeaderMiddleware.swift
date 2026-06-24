//
//  ServerHeaderMiddleware.swift
//  HTTPServer
//
//  A minimal response-decorating middleware: it stamps a `Server` header (RFC 9110 §10.2.4) on every
//  response that does not already carry one. The simplest shape of ``HTTPMiddleware`` — delegate, then
//  adjust the response.
//

public import HTTPCore

/// Adds a `Server` header (RFC 9110 §10.2.4) to responses that lack one.
public struct ServerHeaderMiddleware: HTTPMiddleware {
    private let serverName: String

    /// Creates the middleware, advertising `serverName` (default `"HTTP"`).
    public init(_ serverName: String = "HTTP") {
        self.serverName = serverName
    }

    /// Delegates, then stamps `Server` if the responder did not set it.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body)
        if !response.head.headerFields.contains(.server) {
            _ = response.head.headerFields.append(serverName, for: .server)
        }
        return response
    }
}
