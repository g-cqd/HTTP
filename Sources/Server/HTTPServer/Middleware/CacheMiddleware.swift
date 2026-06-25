//
//  CacheMiddleware.swift
//  HTTPServer
//
//  RFC 9111 — a shared response cache. A safe `GET` whose stored response is still fresh is served
//  straight from the cache with an `Age` header, never reaching the responder; otherwise the responder
//  runs and an explicitly cacheable response (`Cache-Control: max-age`/`s-maxage`, not `no-store` or
//  `private`) is stored, keyed by request and validated against its `Vary`. The store is byte-bounded
//  and LRU (``ResponseCache``). Conservative: only responses with an explicit freshness lifetime are
//  stored (no heuristic caching), and request `no-cache`/`no-store` bypass the cache. Revalidation of a
//  stale entry is a planned follow-up.
//

internal import Foundation
public import HTTPCore

/// An RFC 9111 shared cache: serves a fresh stored `GET` (with `Age`) and stores a cacheable response.
public struct CacheMiddleware: HTTPMiddleware {
    private let cache: ResponseCache
    private let now: @Sendable () -> Int

    /// Creates the cache bounded to `maxBytes`; `now` (seconds, injectable for tests) drives freshness.
    public init(
        maxBytes: Int = 16 * 1_024 * 1_024,
        now: @escaping @Sendable () -> Int = Self.wallClockSeconds
    ) {
        self.cache = ResponseCache(maxBytes: maxBytes)
        self.now = now
    }

    /// Serves a fresh stored response or delegates, storing a cacheable result.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        guard request.method == .get else {
            return await next.respond(to: request, body: body)
        }
        let directives = CacheControl(request.headerFields[.cacheControl])
        let key = Self.key(for: request)
        let instant = now()
        if !directives.noStore, !directives.noCache,
            let hit = cache.lookup(key, request: request, now: instant)
        {
            var response = hit.response
            _ = response.head.headerFields.setValue(String(hit.age), for: .age)
            return response
        }
        let response = await next.respond(to: request, body: body)
        if !directives.noStore, let entry = storableEntry(request, response, now: instant) {
            cache.store(key, entry)
        }
        return response
    }

    /// A storable entry if `response` is cacheable for a shared cache (RFC 9111 §3), else nil.
    private func storableEntry(
        _ request: HTTPRequest,
        _ response: ServerResponse,
        now: Int
    ) -> ResponseCache.Entry? {
        guard response.head.status == .ok else {
            return nil
        }
        let directives = CacheControl(response.head.headerFields[.cacheControl])
        guard !directives.noStore, !directives.isPrivate,
            let lifetime = directives.freshnessLifetime, lifetime > 0
        else {
            return nil
        }
        guard let varyNames = varyFields(response) else {
            return nil  // Vary: * — uncacheable (RFC 9111 §4.1)
        }
        let selecting = varyNames.map { request.headerFields[$0] }
        return ResponseCache.Entry(
            response: response,
            storedAt: now,
            freshFor: lifetime,
            varyNames: varyNames,
            selecting: selecting,
            cost: response.body.count + 256
        )
    }

    /// The `Vary` field names, or nil for `Vary: *` (which makes the response uncacheable).
    private func varyFields(_ response: ServerResponse) -> [HTTPFieldName]? {
        var names: [HTTPFieldName] = []
        for header in response.head.headerFields.values(for: .vary) {
            for token in header.split(separator: ",") {
                let name = token.trimmingCharacters(in: .whitespaces).lowercased()
                if name == "*" {
                    return nil
                }
                if let field = HTTPFieldName(name) {
                    names.append(field)
                }
            }
        }
        return names
    }

    /// The primary cache key: method, authority, and target (RFC 9111 §4 — query is significant).
    private static func key(for request: HTTPRequest) -> String {
        "\(request.method.rawValue) \(request.effectiveAuthority ?? "") \(request.path)"
    }

    /// Wall-clock seconds since the Unix epoch — the default `now`, matching ``DateHeaderMiddleware``.
    public static func wallClockSeconds() -> Int {
        Int(Date().timeIntervalSince1970)
    }
}
