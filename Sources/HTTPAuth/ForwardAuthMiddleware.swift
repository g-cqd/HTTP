//
//  ForwardAuthMiddleware.swift
//  HTTPAuth
//
//  The `auth_request` / `forward_auth` escape hatch. Each request is shown to an injected authorizer that
//  returns allow (with request headers to propagate downstream — e.g. an upstream's `X-User`) or deny (a
//  terminal response). The server has no outbound HTTP client, so the app owns the subrequest to the
//  external authorization service inside the closure (URLSession, an internal client, …).
//

public import HTTPCore
public import HTTPServer

/// Delegates authorization to an injected authorizer — the `auth_request`/`forward_auth` escape hatch.
public struct ForwardAuthMiddleware: HTTPMiddleware {
    /// The authorizer's verdict for a request.
    public enum Decision: Sendable {
        /// Allow the request, asserting `headers` on it for the handler.
        case allow(headers: [(HTTPFieldName, String)])
        /// Reject the request with this terminal response.
        case deny(ServerResponse)
    }

    private let authorize: @Sendable (HTTPRequest) async -> Decision

    /// Creates the middleware delegating each request's authorization to `authorize`.
    public init(_ authorize: @escaping @Sendable (HTTPRequest) async -> Decision) {
        self.authorize = authorize
    }

    /// Asks the authorizer; on allow, propagates its headers and continues; on deny, returns its response.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        switch await authorize(request) {
            case .deny(let response):
                return response
            case .allow(let headers):
                var request = request
                for (name, value) in headers {
                    _ = request.headerFields.setValue(value, for: name)
                }
                return await next.respond(to: request, body: body)
        }
    }
}
