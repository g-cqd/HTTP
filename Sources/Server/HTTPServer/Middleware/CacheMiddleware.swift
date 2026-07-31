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
    private let supervisor: RevalidationSupervisor

    /// Creates the cache bounded to `maxBytes`; `now` (seconds, injectable for tests) drives freshness.
    ///
    /// - Parameters:
    ///   - maxBytes: the accounted size of the stored responses, above which the least-recently-used
    ///     entries are evicted.
    ///   - maxConcurrentRevalidations: how many background `stale-while-revalidate` refreshes (RFC 5861
    ///     §3) may be in flight at once. A refresh over the bound is skipped, not queued — the stale
    ///     response was already served, so a skipped refresh costs freshness, never correctness.
    ///   - revalidationDeadline: how long one background refresh may run. Cooperative — see
    ///     ``RevalidationSupervisor`` for the precise contract.
    ///   - now: wall-clock seconds; injectable so a test can drive freshness deterministically.
    ///   - spawn: detaches a background refresh from the served response. Defaults to an unstructured
    ///     `Task`; a test injects one it can deterministically settle.
    public init(
        maxBytes: Int = 16 * 1_024 * 1_024,
        maxConcurrentRevalidations: Int = 16,
        revalidationDeadline: Duration = .seconds(10),
        now: @escaping @Sendable () -> Int = Self.wallClockSeconds,
        spawn: @escaping @Sendable (@escaping @Sendable () async -> Void) -> Void = { work in
            Task { await work() }
        }
    ) {
        self.cache = ResponseCache(maxBytes: maxBytes)
        self.now = now
        self.supervisor = RevalidationSupervisor(
            maxConcurrent: maxConcurrentRevalidations,
            deadline: revalidationDeadline,
            spawn: spawn
        )
    }

    /// The accounted size of the stored responses, in bytes — never above the configured `maxBytes`.
    ///
    /// Internal rather than private because the byte cap is a claim, and a claim nobody can read is a
    /// claim nobody checks: the regression that pins the bound reads this.
    var storedBytes: Int {
        cache.storedBytes
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
        if !directives.noStore,
            let entry = Self.storableEntry(request, response, key: key, now: instant)
        {
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

    /// Offers a background refresh for `key` to the supervisor, re-running the responder and replacing
    /// the stored entry so later requests are fresh (RFC 5861 §3).
    ///
    /// The supervisor decides: it admits at most one refresh per key (single-flight) and at most
    /// `maxConcurrentRevalidations` overall, taking the permit and the per-key claim in one critical
    /// section. A refusal is silent and correct — the caller has already served the stale response.
    private func revalidate(
        key: String,
        request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) {
        let cache = self.cache
        let now = self.now
        supervisor.submit(key: key) {
            let response = await next.respond(to: request, body: body, context: context)
            if let entry = Self.storableEntry(request, response, key: key, now: now()) {
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
        key: String,
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
            cost: cost(key: key, response, varyNames: varyNames, selecting: selecting)
        )
    }

    /// The bytes to charge the cache for one entry — deliberately an over-estimate.
    ///
    /// The bound this feeds is advertised to operators, who size a process around it. That makes the
    /// two error directions asymmetric: over-counting costs cache hit rate, which is measurable and
    /// tunable, while under-counting silently converts "16 MiB of responses" into an unbounded resident
    /// set, which is CWE-400 with a configuration knob that appears to be working. So every term here
    /// rounds up, and every byte the entry demonstrably owns is counted:
    ///
    /// - the key, which the store owns twice (the dictionary and the LRU slot);
    /// - the buffered body;
    /// - every stored header name and value — a response with 8 KiB of headers and no body used to be
    ///   charged 256 bytes;
    /// - the `Vary` field names and the request values they selected on, which are attacker-influenced
    ///   in both count and length (a `Vary: accept-language` entry stores whatever the client sent);
    /// - ``ResponseCache/minimumEntryCost`` per entry, for the dictionary slot, the LRU slot, the
    ///   `Entry` struct, and the heap-object header on each of the five separate allocations an entry
    ///   pulls in (the key string, the body array, the field array, and the two `Vary` arrays);
    /// - ``fieldOverhead`` per header line and ``elementOverhead`` per `Vary` element, for the same
    ///   per-element struct-and-allocator overhead the raw byte counts do not include.
    ///
    /// The constants are round numbers, not measurements. Measuring them would imply a precision that
    /// the allocator's size classes do not offer, and a too-large constant is the safe direction.
    private static func cost(
        key: String,
        _ response: ServerResponse,
        varyNames: [HTTPFieldName],
        selecting: [String?]
    ) -> Int {
        var total = ResponseCache.minimumEntryCost + key.utf8.count + response.body.count
        for field in response.head.headerFields {
            total += fieldOverhead + field.name.canonicalName.utf8.count + field.value.utf8.count
        }
        for name in varyNames {
            total += elementOverhead + name.canonicalName.utf8.count
        }
        for value in selecting {
            total += elementOverhead + (value?.utf8.count ?? 0)
        }
        return total
    }

    /// Charged per stored header line, on top of its name and value bytes.
    ///
    /// Covers the `HTTPField` struct in the field array (a name enum plus two `String` headers) and the
    /// heap allocation each of those strings makes once it outgrows the small-string form.
    private static let fieldOverhead = 128

    /// Charged per `Vary` name and per selecting value, on top of the value's own bytes.
    private static let elementOverhead = 64

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
    /// ignored (the entry simply has no stale-serving window) and a huge one is clamped to
    /// ``CacheControl/deltaSecondsCeiling`` (RFC 9111 §1.2.2).
    ///
    /// The clamp is load-bearing, not cosmetic. ``ResponseCache`` adds this window to the freshness
    /// lifetime to decide whether a stale entry is still servable, and that sum is only evaluated once
    /// the entry has actually gone stale. `Cache-Control: max-age=60, stale-while-revalidate=<Int.max>`
    /// is a perfectly parseable header that reaches that addition sixty seconds later and traps the
    /// process — a remotely triggered crash, not a wrong answer. Clamping both operands to 2^31 makes
    /// the sum unrepresentably small by comparison.
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
            if let seconds = CacheControl.deltaSeconds(argument), seconds > 0 {
                return seconds
            }
        }
        return nil
    }

    /// The primary cache key: method, authority, and target (RFC 9111 §4 — query is significant).
    static func key(for request: HTTPRequest) -> String {
        "\(request.method.rawValue) \(request.effectiveAuthority ?? "") \(request.path)"
    }

    /// Wall-clock seconds since the Unix epoch — the default `now`, matching ``DateHeaderMiddleware``.
    public static func wallClockSeconds() -> Int {
        Int(Date().timeIntervalSince1970)
    }
}
