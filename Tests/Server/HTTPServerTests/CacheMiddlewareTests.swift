//
//  CacheMiddlewareTests.swift
//  HTTPServerTests
//
//  RFC 9111 — the shared response cache: a fresh stored GET is served with an Age header (a hit), a
//  stale or uncacheable response is not (the responder runs again), Vary keys the cache on the selecting
//  request header, and the byte cap evicts the least-recently-used entry. A cache hit is detected by the
//  presence of the Age header (only a served-from-cache response carries it).
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTPServer

@Suite("Middleware — shared response cache (RFC 9111)")
struct CacheMiddlewareTests {
    private func responder(
        cacheControl: String?,
        vary: String? = nil,
        body: String = "payload"
    ) -> any HTTPResponder {
        ClosureResponder { _, _, _ in
            var fields = HTTPFields()
            if let cacheControl { _ = fields.setValue(cacheControl, for: .cacheControl) }
            if let vary { _ = fields.setValue(vary, for: .vary) }
            let head = HTTPResponse(status: .ok, headerFields: fields)
            return ServerResponse(head, body: Array(body.utf8))
        }
    }

    private func get(
        method: HTTPMethod = .get,
        path: String = "/",
        cacheControl: String? = nil,
        acceptLanguage: String? = nil
    ) -> HTTPRequest {
        var fields = HTTPFields()
        if let cacheControl { _ = fields.append(cacheControl, for: .cacheControl) }
        if let acceptLanguage { _ = fields.append(acceptLanguage, for: .acceptLanguage) }
        return HTTPRequest(
            method: method, scheme: "https", authority: "x", path: path, headerFields: fields
        )
    }

    @Test("a fresh stored response is served from the cache with an Age header")
    func servesFresh() async {
        let middleware = CacheMiddleware()
        let next = responder(cacheControl: "max-age=60")
        let miss = await middleware.respond(to: get(), body: [], next: next)
        #expect(miss.head.headerFields[.age] == nil)  // first time — straight from the responder
        let hit = await middleware.respond(to: get(), body: [], next: next)
        #expect(hit.head.headerFields[.age] != nil)  // served from the cache
        #expect(hit.body == Array("payload".utf8))
    }

    @Test("a stale entry is not served — the responder runs again (RFC 9111 §4.2)")
    func staleNotServed() async {
        let clock = TestClock()
        let now: @Sendable () -> Int = { Int(clock.monotonicNanoseconds / 1_000_000_000) }
        let middleware = CacheMiddleware(now: now)
        let next = responder(cacheControl: "max-age=10")
        _ = await middleware.respond(to: get(), body: [], next: next)
        let fresh = await middleware.respond(to: get(), body: [], next: next)
        #expect(fresh.head.headerFields[.age] != nil)
        clock.advance(by: .seconds(11))
        let stale = await middleware.respond(to: get(), body: [], next: next)
        #expect(stale.head.headerFields[.age] == nil)
    }

    @Test("a response without an explicit freshness lifetime is not stored (no heuristic caching)")
    func noLifetimeNotStored() async {
        let middleware = CacheMiddleware()
        let next = responder(cacheControl: nil)
        _ = await middleware.respond(to: get(), body: [], next: next)
        let again = await middleware.respond(to: get(), body: [], next: next)
        #expect(again.head.headerFields[.age] == nil)
    }

    @Test(
        "an uncacheable directive (no-store / private) keeps the response out of the shared cache",
        arguments: ["max-age=60, no-store", "max-age=60, private"]
    )
    func uncacheableDirectives(_ cacheControl: String) async {
        let middleware = CacheMiddleware()
        let next = responder(cacheControl: cacheControl)
        _ = await middleware.respond(to: get(), body: [], next: next)
        let again = await middleware.respond(to: get(), body: [], next: next)
        #expect(again.head.headerFields[.age] == nil)
    }

    @Test("request no-cache bypasses a fresh stored response (RFC 9111 §5.2.1.4)")
    func requestNoCacheBypasses() async {
        let middleware = CacheMiddleware()
        let next = responder(cacheControl: "max-age=60")
        _ = await middleware.respond(to: get(), body: [], next: next)
        let bypass = await middleware.respond(
            to: get(cacheControl: "no-cache"), body: [], next: next
        )
        #expect(bypass.head.headerFields[.age] == nil)
    }

    @Test("Vary keys the cache on the selecting request header (RFC 9111 §4.1)")
    func variesOnHeader() async {
        let middleware = CacheMiddleware()
        let next = responder(cacheControl: "max-age=60", vary: "accept-language")
        _ = await middleware.respond(to: get(acceptLanguage: "en"), body: [], next: next)
        let hit = await middleware.respond(to: get(acceptLanguage: "en"), body: [], next: next)
        #expect(hit.head.headerFields[.age] != nil)  // same variant
        let other = await middleware.respond(to: get(acceptLanguage: "fr"), body: [], next: next)
        #expect(other.head.headerFields[.age] == nil)  // different variant
    }

    @Test("Vary: * makes a response uncacheable")
    func varyStarUncacheable() async {
        let middleware = CacheMiddleware()
        let next = responder(cacheControl: "max-age=60", vary: "*")
        _ = await middleware.respond(to: get(), body: [], next: next)
        let again = await middleware.respond(to: get(), body: [], next: next)
        #expect(again.head.headerFields[.age] == nil)
    }

    @Test("a non-GET request is not cached")
    func nonGetNotCached() async {
        let middleware = CacheMiddleware()
        let next = responder(cacheControl: "max-age=60")
        _ = await middleware.respond(to: get(method: .post), body: [], next: next)
        let getResponse = await middleware.respond(to: get(), body: [], next: next)
        #expect(getResponse.head.headerFields[.age] == nil)
    }

    @Test("the byte cap evicts the least-recently-used entry (CWE-400)")
    func evictsLRU() async {
        let middleware = CacheMiddleware(maxBytes: 300)  // ~one entry (256 overhead each)
        let next = responder(cacheControl: "max-age=60", body: "")
        _ = await middleware.respond(to: get(path: "/a"), body: [], next: next)
        _ = await middleware.respond(to: get(path: "/b"), body: [], next: next)  // evicts /a
        let evicted = await middleware.respond(to: get(path: "/a"), body: [], next: next)
        #expect(evicted.head.headerFields[.age] == nil)
    }

    @Test("a cache hit promotes an entry so it survives a later eviction (intrusive-list touch)")
    func hitPromotesPastEviction() async {
        let middleware = CacheMiddleware(maxBytes: 600)  // ~two entries (256 overhead each)
        let next = responder(cacheControl: "max-age=60", body: "")
        _ = await middleware.respond(to: get(path: "/a"), body: [], next: next)  // store /a
        _ = await middleware.respond(to: get(path: "/b"), body: [], next: next)  // store /b
        // Touch /a so it is most-recently-used; /b becomes the LRU.
        let promoted = await middleware.respond(to: get(path: "/a"), body: [], next: next)
        #expect(promoted.head.headerFields[.age] != nil)
        // Store /c — over the two-entry cap, so the LRU (/b) is evicted.
        _ = await middleware.respond(to: get(path: "/c"), body: [], next: next)
        // Check /a first: a hit re-promotes without a store, so it does not perturb /b's state.
        let aSurvives = await middleware.respond(to: get(path: "/a"), body: [], next: next)
        #expect(aSurvives.head.headerFields[.age] != nil)  // promoted earlier, retained
        let bEvicted = await middleware.respond(to: get(path: "/b"), body: [], next: next)
        #expect(bEvicted.head.headerFields[.age] == nil)  // was the LRU, dropped by /c
    }
}
