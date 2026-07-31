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
        // Room for one entry: an empty-bodied response with one header costs ~671 accounted bytes.
        let middleware = CacheMiddleware(maxBytes: 900)
        let next = responder(cacheControl: "max-age=60", body: "")
        _ = await middleware.respond(to: get(path: "/a"), body: [], next: next)
        _ = await middleware.respond(to: get(path: "/b"), body: [], next: next)  // evicts /a
        let evicted = await middleware.respond(to: get(path: "/a"), body: [], next: next)
        #expect(evicted.head.headerFields[.age] == nil)
    }

    @Test("a cache hit promotes an entry so it survives a later eviction (intrusive-list touch)")
    func hitPromotesPastEviction() async {
        // Room for two ~671-byte entries and not a third.
        let middleware = CacheMiddleware(maxBytes: 1_800)
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

    /// One row of the delta-seconds clamping table: what the origin sent, how far time moved, and
    /// whether the second request is then served from the cache.
    struct DeltaSecondsCase: Sendable, CustomStringConvertible {
        let cacheControl: String
        let after: Int
        let served: Bool

        init(_ cacheControl: String, after: Int, served: Bool) {
            self.cacheControl = cacheControl
            self.after = after
            self.served = served
        }

        var description: String { "\(cacheControl) after \(after)s" }
    }

    /// `Int.max` spelled out — a `delta-seconds` argument this machine can represent but must not use.
    static let intMaxSeconds = "9223372036854775807"

    /// The RFC 9111 §1.2.2 clamping table, hoisted so each row fits on one line.
    static let deltaSecondsCases: [DeltaSecondsCase] = [
        // Exactly `Int.max`: representable, but far past the 2^31 ceiling §1.2.2 makes mandatory —
        // clamped, so the entry is still fresh three thousand seconds later.
        DeltaSecondsCase("max-age=\(intMaxSeconds)", after: 3_000, served: true),
        // Beyond `Int.max`: a valid `delta-seconds` production this machine cannot represent, which
        // §1.2.2 says to treat as the ceiling, NOT (as it did) as "no freshness lifetime at all".
        DeltaSecondsCase("max-age=99999999999999999999", after: 3_000, served: true),
        // The ceiling is a ceiling, not infinity: past 2^31 seconds the entry really is stale.
        DeltaSecondsCase("max-age=\(intMaxSeconds)", after: 2_147_483_649, served: false),
        // `delta-seconds` is `1*DIGIT`: neither of these is one, so the directive is unparseable and
        // ignored (§5.2) and the response has no explicit lifetime — not stored at all.
        DeltaSecondsCase("max-age=-1", after: 0, served: false),
        DeltaSecondsCase("max-age=abc", after: 0, served: false),
        // The pair the audit cites. It does NOT in fact overflow: the entry never goes stale, so
        // `freshFor + window` is never evaluated. Kept as the regression it was reported as.
        DeltaSecondsCase(
            "max-age=\(intMaxSeconds), stale-while-revalidate=1", after: 3_000, served: true
        ),
        // The pair that does: a small lifetime with a huge window, so the entry goes stale and the
        // addition IS evaluated. Unclamped this trapped the process; clamped it is inside the window.
        DeltaSecondsCase(
            "max-age=60, stale-while-revalidate=\(intMaxSeconds)", after: 3_000, served: true
        ),
        // `s-maxage` reaches the same arithmetic and needs the same clamp.
        DeltaSecondsCase("s-maxage=\(intMaxSeconds)", after: 3_000, served: true)
    ]

    @Test(
        "a max-age past the RFC 9111 delta-seconds ceiling is clamped, not trapped",
        arguments: Self.deltaSecondsCases
    )
    func clampsDeltaSecondsToTheCeiling(_ testCase: DeltaSecondsCase) async {
        let clock = TestClock()
        let now: @Sendable () -> Int = { Int(clock.monotonicNanoseconds / 1_000_000_000) }
        let middleware = CacheMiddleware(now: now) { _ in
            // Clamping is decided before any refresh runs; dropping the spawned work keeps this
            // deterministic and keeps the stale rows from reaching the origin a second time.
        }
        let next = responder(cacheControl: testCase.cacheControl)
        _ = await middleware.respond(to: get(), body: [], next: next)
        clock.advance(by: .seconds(testCase.after))
        let response = await middleware.respond(to: get(), body: [], next: next)
        #expect((response.head.headerFields[.age] != nil) == testCase.served)
    }

    /// A responder carrying a deliberately fat header section and a `Vary`, so the accounted cost has
    /// to reach past the body to be right.
    private func paddedResponder(padding: String, body: String) -> any HTTPResponder {
        ClosureResponder { _, _, _ in
            var fields = HTTPFields()
            _ = fields.setValue("max-age=60", for: .cacheControl)
            _ = fields.setValue("accept-language", for: .vary)
            if let padded = HTTPField(name: "x-padding", value: padding) {
                fields.append(padded)
            }
            let head = HTTPResponse(status: .ok, headerFields: fields)
            return ServerResponse(head, body: Array(body.utf8))
        }
    }

    @Test("stored bytes never exceed the configured cap under mixed entry sizes")
    func costAccountsForEverythingStored() async {
        let padding = String(repeating: "p", count: 2_048)
        let language = String(repeating: "l", count: 512)
        let body = String(repeating: "b", count: 100)
        let cap = 64 * 1_024
        let middleware = CacheMiddleware(maxBytes: cap)
        let request = get(acceptLanguage: language)
        let next = paddedResponder(padding: padding, body: body)
        _ = await middleware.respond(to: request, body: [], next: next)

        // A lower bound measured from what actually went in, not from the formula under test: the
        // cache demonstrably owns at least these bytes, so anything smaller is an under-count.
        let measured =
            CacheMiddleware.key(for: request).utf8.count
            + body.utf8.count
            + "cache-control".utf8.count + "max-age=60".utf8.count
            + "vary".utf8.count + "accept-language".utf8.count
            + "x-padding".utf8.count + padding.utf8.count
            + "accept-language".utf8.count  // the Vary name stored with the entry
            + language.utf8.count  // the request value it selected on
        #expect(middleware.storedBytes >= measured)
        #expect(middleware.storedBytes <= cap)

        // Mixed sizes against a tight cap: the advertised bound holds after every single store.
        let tightCap = 8 * 1_024
        let tight = CacheMiddleware(maxBytes: tightCap)
        for index in 0 ..< 64 {
            let sized = paddedResponder(
                padding: String(repeating: "p", count: index * 64),
                body: body
            )
            let path = "/\(index)"
            _ = await tight.respond(
                to: get(path: path, acceptLanguage: language),
                body: [],
                next: sized
            )
            #expect(tight.storedBytes <= tightCap)
        }
        #expect(tight.storedBytes > 0)  // the cap bounds the store, it does not empty it
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
