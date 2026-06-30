//
//  CacheMiddleware.swift
//  HTTPServer
//
//  RFC 9111 — a shared response cache. A safe `GET` whose stored response is still fresh is served
//  straight from the cache with an `Age` header, never reaching the responder; otherwise the responder
//  runs and an explicitly cacheable response (`Cache-Control: max-age`/`s-maxage`, not `no-store` or
//  `private`) is stored, keyed by request and validated against its `Vary`. The store is byte-bounded
//  and LRU (``ResponseCache``). Conservative: only responses with an explicit freshness lifetime are
//  stored (no heuristic caching), and request `no-cache`/`no-store` bypass the cache. A stale entry
//  whose stored response carried `stale-while-revalidate=N` (RFC 5861 §3) is still served immediately
//  inside that N-second window while one background revalidation refreshes it for later requests.
//

internal import Foundation
public import HTTPCore

/// An RFC 9111 shared cache: serves a fresh (or briefly stale) stored `GET` and stores a response.
public struct CacheMiddleware: HTTPMiddleware {
    private let cache: ResponseCache
    private let now: @Sendable () -> Int
    private let spawn: @Sendable (@escaping @Sendable () async -> Void) -> Void

    /// Creates the cache bounded to `maxBytes`; `now` (seconds, injectable for tests) drives freshness.
    ///
    /// `spawn` runs a background `stale-while-revalidate` refresh (RFC 5861 §3) detached from the served
    /// response; it defaults to an unstructured `Task` and a test injects one it can deterministically
    /// settle.
    public init(
        maxBytes: Int = 16 * 1_024 * 1_024,
        now: @escaping @Sendable () -> Int = Self.wallClockSeconds,
        spawn: @escaping @Sendable (@escaping @Sendable () async -> Void) -> Void = { work in
            Task { await work() }
        }
    ) {
        self.cache = ResponseCache(maxBytes: maxBytes)
        self.now = now
        self.spawn = spawn
    }

    /// Serves a fresh (or briefly stale) stored response or delegates, storing a cacheable result.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        guard request.method == .get else {
            return await next.respond(to: request, body: body, context: context)
        }
        let directives = CacheControl(request.headerFields[.cacheControl])
        let key = Self.key(for: request)
        let instant = now()
        if !directives.noStore, !directives.noCache,
            let hit = cache.lookup(key, request: request, now: instant)
        {
            return served(
                hit, key: key, request: request, body: body, context: context, next: next
            )
        }
        let response = await next.respond(to: request, body: body, context: context)
        if !directives.noStore, let entry = Self.storableEntry(request, response, now: instant) {
            cache.store(key, entry)
        }
        return response
    }

    /// The stored response to return, tagging it with `Age` and triggering background revalidation when
    /// it is being served stale within its `stale-while-revalidate` window (RFC 5861 §3).
    private func served(
        _ hit: ResponseCache.Lookup,
        key: String,
        request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) -> ServerResponse {
        switch hit {
            case .fresh(let response, let age):
                return aged(response, age)
            case .staleWhileRevalidate(let response, let age):
                revalidate(key: key, request: request, body: body, context: context, next: next)
                return aged(response, age)
        }
    }

    /// `response` with its `Age` header set to `age` seconds (RFC 9111 §5.1).
    private func aged(_ response: ServerResponse, _ age: Int) -> ServerResponse {
        var response = response
        _ = response.head.headerFields.setValue(String(age), for: .age)
        return response
    }

    /// Spawns a single background refresh for `key` (at most one in flight), re-running the responder and
    /// replacing the stored entry so later requests are fresh (RFC 5861 §3).
    private func revalidate(
        key: String,
        request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) {
        guard cache.beginRevalidation(key) else {
            return  // a refresh for this key is already running — single-flight
        }
        let cache = self.cache
        let now = self.now
        spawn {
            defer { cache.finishRevalidation(key) }
            let response = await next.respond(to: request, body: body, context: context)
            if let entry = Self.storableEntry(request, response, now: now()) {
                cache.store(key, entry)
            }
        }
    }

    /// A storable entry if `response` is cacheable for a shared cache (RFC 9111 §3), else nil.
    ///
    /// Static so the detached revalidation closure can build an entry without capturing `self`.
    private static func storableEntry(
        _ request: HTTPRequest,
        _ response: ServerResponse,
        now: Int
    ) -> ResponseCache.Entry? {
        guard response.stream == nil, response.head.status == .ok else {
            return nil  // a streamed body has no buffered bytes to store (P6)
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
            staleWhileRevalidate: staleWhileRevalidate(response.head.headerFields[.cacheControl]),
            varyNames: varyNames,
            selecting: selecting,
            cost: response.body.count + 256
        )
    }

    /// The `Vary` field names, or nil for `Vary: *` (which makes the response uncacheable).
    private static func varyFields(_ response: ServerResponse) -> [HTTPFieldName]? {
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

    /// The non-negative `stale-while-revalidate=N` window (seconds) from a `Cache-Control` value, or nil.
    ///
    /// Parsed here rather than in ``CacheControl`` because only this cache acts on the directive (RFC
    /// 5861 §3); the value is a `delta-seconds`, so a missing, negative, or non-numeric argument is
    /// ignored (the entry simply has no stale-serving window).
    private static func staleWhileRevalidate(_ value: String?) -> Int? {
        guard let value else {
            return nil
        }
        for directive in value.split(separator: ",") {
            let token = directive.trimmingCharacters(in: .whitespaces)
            guard let separator = token.firstIndex(of: "=") else {
                continue
            }
            let name = token[..<separator].trimmingCharacters(in: .whitespaces).lowercased()
            guard name == "stale-while-revalidate" else {
                continue
            }
            let value = token[token.index(after: separator)...]
            let argument = value.trimmingCharacters(in: .whitespaces)
            if let seconds = Int(argument), seconds > 0 {
                return seconds
            }
        }
        return nil
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
