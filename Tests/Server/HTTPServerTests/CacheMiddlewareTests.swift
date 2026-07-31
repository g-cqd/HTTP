//
//  CacheMiddlewareTests.swift
//  HTTPServerTests
//
//  RFC 9111 — the shared response cache: a fresh stored GET is served with an Age header (a hit), a
//  stale or uncacheable response is not (the responder runs again), Vary keys the cache on the selecting
//  request header, and the byte cap evicts the least-recently-used entry. A cache hit is detected by the
//  presence of the Age header (only a served-from-cache response carries it).
//
//  Also the audit finding 14 regressions: the store must release every entry when the cache itself is
//  dropped (CWE-401 — the `class`-node recency list this replaced could not), and it must never exceed
//  its advertised byte cap.
//

import HTTPCore
import HTTPTestSupport
import Synchronization
import Testing

@testable import HTTPServer

@Suite("Middleware — shared response cache (RFC 9111)")
struct CacheMiddlewareTests {
    /// A per-test deallocation tally, so the leak probe needs no process-wide (racy) static counter.
    private final class DeallocationCounter: Sendable {
        private let tally = Atomic<Int>(0)

        /// How many ``TrackedPayload`` instances have deallocated.
        var value: Int { tally.load(ordering: .relaxed) }

        /// Records one deallocation.
        func record() { tally.wrappingAdd(1, ordering: .relaxed) }

        deinit {
            // No teardown beyond ARC.
        }
    }

    /// A reference-typed payload smuggled into a stored ``ServerResponse`` so its release is observable.
    ///
    /// The store holds only value types, so a leak is invisible to a value-level assertion; a class
    /// captured by the response's ``ResponseStream`` closure makes "the cache still owns this" a
    /// countable fact.
    private final class TrackedPayload: Sendable {
        private let counter: DeallocationCounter

        /// The bytes the captured stream would write — kept empty; only the capture matters.
        let bytes: [UInt8] = []

        init(_ counter: DeallocationCounter) {
            self.counter = counter
        }

        deinit {
            counter.record()
        }
    }

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

    @Test("a dropped cache deallocates every stored response (CWE-401, audit finding 14)")
    func droppedCacheReleasesEveryEntry() {
        let counter = DeallocationCounter()
        let total = 8
        var cache: ResponseCache? = ResponseCache(maxBytes: 1_024 * 1_024)
        for index in 0 ..< total {
            cache?.store("GET x /\(index)", Self.trackedEntry(counter))
        }
        #expect(counter.value == 0)  // still stored — nothing released yet
        cache = nil
        // The recency list this replaced threaded `class` nodes with strong `prev` AND `next`, so a
        // two-or-more-entry list was an ARC cycle: dropping the cache released nothing at all.
        #expect(counter.value == total)
    }

    /// A storable entry whose response captures a ``TrackedPayload``, so its release is countable.
    private static func trackedEntry(_ counter: DeallocationCounter) -> ResponseCache.Entry {
        let payload = TrackedPayload(counter)
        let stream = ResponseStream { writer in try await writer.write(payload.bytes) }
        return ResponseCache.Entry(
            response: ServerResponse(HTTPResponse(status: .ok), stream: stream),
            storedAt: 0,
            freshFor: 60,
            staleWhileRevalidate: nil,
            varyNames: [],
            selecting: [],
            cost: 1_024
        )
    }
}
