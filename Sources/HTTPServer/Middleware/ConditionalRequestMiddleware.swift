//
//  ConditionalRequestMiddleware.swift
//  HTTPServer
//
//  Conditional requests (RFC 9110 §13). For a successful GET/HEAD the middleware derives an `ETag`
//  validator from the body (unless the responder set one), then — if the request's `If-None-Match`
//  matches (weak comparison, §13.1.2) — collapses the response to `304 Not Modified` with no body,
//  saving the transfer. The validator is `"<size>-<crc32>"`: a collision needs the same length *and*
//  CRC-32, which is strong enough for a cache validator and needs no crypto.
//

internal import Foundation
public import HTTPCore

/// Adds `ETag` validators and answers `If-None-Match` with `304 Not Modified` (RFC 9110 §13).
public struct ConditionalRequestMiddleware: HTTPMiddleware {
    /// Creates the middleware.
    public init() {
        // Stateless; nothing to configure.
    }

    /// Delegates, tags a cacheable response with an `ETag`, and returns `304` when it still matches.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body)
        guard isCacheable(request, response) else {
            return response
        }
        let etag = response.head.headerFields[.etag] ?? Self.entityTag(for: response.body)
        _ = response.head.headerFields.setValue(etag, for: .etag)

        guard matches(request.headerFields.values(for: .ifNoneMatch), etag) else {
            return response
        }
        // 304 carries the validators but no content (RFC 9110 §15.4.5).
        var notModified = HTTPResponse(status: .notModified)
        _ = notModified.headerFields.setValue(etag, for: .etag)
        if let cacheControl = response.head.headerFields[.cacheControl] {
            _ = notModified.headerFields.setValue(cacheControl, for: .cacheControl)
        }
        return ServerResponse(notModified)
    }

    /// Only a successful, bodied GET/HEAD response is validated (RFC 9110 §13 / §9.3.1–2).
    private func isCacheable(_ request: HTTPRequest, _ response: ServerResponse) -> Bool {
        (request.method == .get || request.method == .head)
            && response.head.status == .ok && !response.body.isEmpty
    }

    /// A strong entity-tag for `body`: `"<hex size>-<hex CRC-32>"` (RFC 9110 §8.8.3).
    private static func entityTag(for body: [UInt8]) -> String {
        "\"\(String(body.count, radix: 16))-\(String(CRC32.checksum(body), radix: 16))\""
    }

    /// Whether any `If-None-Match` entry matches `etag` under weak comparison (RFC 9110 §13.1.2);
    /// `*` matches any current representation.
    private func matches(_ ifNoneMatch: [String], _ etag: String) -> Bool {
        let target = Self.opaque(etag)
        for value in ifNoneMatch {
            for element in value.split(separator: ",") {
                let candidate = element.trimmingCharacters(in: .whitespaces)
                if candidate == "*" || Self.opaque(candidate) == target {
                    return true
                }
            }
        }
        return false
    }

    /// The opaque-tag of an entity-tag — its value with any weak `W/` prefix removed (RFC 9110 §8.8.3).
    private static func opaque(_ tag: some StringProtocol) -> String {
        tag.hasPrefix("W/") ? String(tag.dropFirst(2)) : String(tag)
    }
}
