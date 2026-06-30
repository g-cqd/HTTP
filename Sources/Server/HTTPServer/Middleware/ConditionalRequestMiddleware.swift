//
//  ConditionalRequestMiddleware.swift
//  HTTPServer
//
//  Conditional requests (RFC 9110 §13). For a successful GET/HEAD the middleware derives validators —
//  an `ETag` from the body (unless the responder set one) and any responder-supplied `Last-Modified` —
//  then evaluates the request's preconditions in the order §13.2.2 mandates: `If-Match` /
//  `If-Unmodified-Since` gate with `412 Precondition Failed`, and `If-None-Match` / `If-Modified-Since`
//  collapse an unchanged representation to `304 Not Modified` with no body. The ETag is
//  `"<size>-<crc32>"` — strong enough for a cache validator, no crypto.
//
//  Scope: GET/HEAD. A precondition on an unsafe method (PUT/DELETE) must be enforced by the handler
//  *before* it mutates state; a response-decorating middleware runs too late to prevent the mutation.
//

public import HTTPCore

/// Adds validators and evaluates the conditional-request preconditions (RFC 9110 §13).
public struct ConditionalRequestMiddleware: HTTPMiddleware {
    /// Creates the middleware.
    public init() {
        // Stateless; nothing to configure.
    }

    /// Delegates, tags a cacheable response with an `ETag`, then applies the §13.2.2 precondition order.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body, context: context)
        guard isCacheable(request, response) else {
            return response
        }
        let etag = response.head.headerFields[.etag] ?? EntityTag.crc(for: response.body)
        _ = response.head.headerFields.setValue(etag, for: .etag)
        let lastModified = response.head.headerFields[.lastModified].flatMap(HTTPDate.parse)

        // (1) If-Match, else (2) If-Unmodified-Since — a failed state precondition is 412 (§13.2.2).
        if failsStatePrecondition(request, etag: etag, lastModified: lastModified) {
            return ServerResponse(HTTPResponse(status: .preconditionFailed))
        }
        // (3) If-None-Match, else (4) If-Modified-Since — an unchanged representation is 304.
        if isNotModified(request, etag: etag, lastModified: lastModified) {
            return notModified(etag: etag, from: response)
        }
        return response
    }

    /// Only a successful, bodied GET/HEAD response is validated (RFC 9110 §13 / §9.3.1–2).
    private func isCacheable(_ request: HTTPRequest, _ response: ServerResponse) -> Bool {
        (request.method == .get || request.method == .head)
            && response.head.status == .ok && !response.body.isEmpty
    }

    /// Whether `If-Match` (strong) or, in its absence, `If-Unmodified-Since` fails (RFC 9110 §13.2.2).
    private func failsStatePrecondition(
        _ request: HTTPRequest,
        etag: String,
        lastModified: Int?
    ) -> Bool {
        let ifMatch = request.headerFields.values(for: .ifMatch)
        if !ifMatch.isEmpty {
            return !EntityTag.strongMatches(ifMatch, etag)
        }
        let ifUnmodifiedSince = request.headerFields[.ifUnmodifiedSince].flatMap(HTTPDate.parse)
        guard let ifUnmodifiedSince, let lastModified else {
            return false
        }
        // Modified after the date → the precondition is false (412).
        return lastModified > ifUnmodifiedSince
    }

    /// Whether `If-None-Match` (weak) matches or, in its absence, `If-Modified-Since` is unmet — the
    /// representation is unchanged, so the response collapses to 304 (RFC 9110 §13.2.2).
    private func isNotModified(
        _ request: HTTPRequest,
        etag: String,
        lastModified: Int?
    ) -> Bool {
        let ifNoneMatch = request.headerFields.values(for: .ifNoneMatch)
        if !ifNoneMatch.isEmpty {
            return EntityTag.weakMatches(ifNoneMatch, etag)
        }
        let ifModifiedSince = request.headerFields[.ifModifiedSince].flatMap(HTTPDate.parse)
        guard let ifModifiedSince, let lastModified else {
            return false
        }
        // Not modified since the date → 304.
        return lastModified <= ifModifiedSince
    }

    /// A `304` carrying the validators but no content (RFC 9110 §15.4.5).
    private func notModified(etag: String, from response: ServerResponse) -> ServerResponse {
        var head = HTTPResponse(status: .notModified)
        _ = head.headerFields.setValue(etag, for: .etag)
        if let cacheControl = response.head.headerFields[.cacheControl] {
            _ = head.headerFields.setValue(cacheControl, for: .cacheControl)
        }
        if let lastModified = response.head.headerFields[.lastModified] {
            _ = head.headerFields.setValue(lastModified, for: .lastModified)
        }
        return ServerResponse(head)
    }
}
