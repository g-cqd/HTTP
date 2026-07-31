//
//  BodyLimitMiddleware.swift
//  HTTPServer
//
//  Rejects a request whose decoded body exceeds an application limit with `413 Content Too Large`
//  (RFC 9110 §15.5.14) — a short-circuit on the request side. Complements the transport-level
//  ``HTTPLimits/maxBodySize`` with a per-application (or, when composed per route, per-route) cap.
//
//  The limit is enforced *while forwarding*: chunks reach the next responder one at a time and are
//  charged as they pass, so a guarded route keeps streaming and an over-limit body trips on the
//  crossing chunk instead of being buffered whole first (CWE-400).
//

public import HTTPCore

/// Short-circuits requests whose body exceeds `maxBytes` with `413 Content Too Large`.
///
/// This bounds the body **as it arrives on the wire**. A middleware that *transforms* the body —
/// decompression, decryption, any decoder — produces bytes this limit never saw, so it must carry its
/// own post-transform cap: a wire-body limit says nothing about what a decoder expands that body into
/// (CWE-409). ``DecompressionMiddleware`` bounds its own output for exactly this reason.
public struct BodyLimitMiddleware: HTTPMiddleware {
    private let maxBytes: Int

    /// Creates the middleware with the maximum accepted body size in octets.
    public init(maxBytes: Int) {
        self.maxBytes = maxBytes
    }

    /// Returns `413` without delegating when `body` is too large; otherwise continues the chain.
    ///
    /// An already-buffered body is measured directly — it is resident either way, so there is nothing
    /// to gain by re-reading it. A streamed body is forwarded through a ``ForwardingByteBudget``,
    /// which ends the stream on the crossing chunk; the responder's answer is then discarded in
    /// favour of `413`, because a handler that ran on a truncated body must not reply as if it were
    /// complete.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        if let bytes = body.bytes {
            guard bytes.count <= maxBytes else {
                return ServerResponse(HTTPResponse(status: .contentTooLarge))
            }
            return await next.respond(to: request, body: body, context: context)
        }
        let budget = ForwardingByteBudget(forwarding: body.asStream, limit: maxBytes)
        let response = await next.respond(to: request, body: budget.makeBody(), context: context)
        guard budget.isExceeded else {
            return response
        }
        return ServerResponse(HTTPResponse(status: .contentTooLarge))
    }
}
