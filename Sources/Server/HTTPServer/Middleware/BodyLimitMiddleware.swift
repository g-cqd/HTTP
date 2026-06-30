//
//  BodyLimitMiddleware.swift
//  HTTPServer
//
//  Rejects a request whose decoded body exceeds an application limit with `413 Content Too Large`
//  (RFC 9110 §15.5.14) — a short-circuit on the request side. Complements the transport-level
//  ``HTTPLimits/maxBodySize`` with a per-application (or, when composed per route, per-route) cap.
//

public import HTTPCore

/// Short-circuits requests whose body exceeds `maxBytes` with `413 Content Too Large`.
public struct BodyLimitMiddleware: HTTPMiddleware {
    private let maxBytes: Int

    /// Creates the middleware with the maximum accepted body size in octets.
    public init(maxBytes: Int) {
        self.maxBytes = maxBytes
    }

    /// Returns `413` without delegating when `body` is too large; otherwise continues the chain.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        // Collect to measure the decoded size, then forward the buffered form on. (Pre-buffer rejection
        // for a streamed body is the engine's per-route limit, Phase 1.2.)
        let bytes = await body.collect()
        guard bytes.count <= maxBytes else {
            return ServerResponse(HTTPResponse(status: .contentTooLarge))
        }
        return await next.respond(to: request, body: .collected(bytes), context: context)
    }
}
