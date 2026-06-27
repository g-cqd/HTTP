//
//  CacheStaleWhileRevalidateTests.swift
//  HTTPServerTests
//
//  RFC 5861 §3 — `stale-while-revalidate`: a stale stored GET whose response carried
//  `stale-while-revalidate=N` is served immediately (with an Age header) for N seconds past freshness
//  while one background revalidation refreshes it, so a later request is fresh; past the window it is
//  not served stale. Time is the deterministic ``TestClock`` and the background refresh runs through an
//  injected spawn the test settles by awaiting the task — no wall clock, no `Task.sleep`.
//

import HTTPCore
import HTTPTestSupport
import Synchronization
import Testing

@testable import HTTPServer

@Suite("Middleware — stale-while-revalidate (RFC 5861 §3)")
struct CacheStaleWhileRevalidateTests {
    /// Captures the background-revalidation closures the middleware spawns, to be run on demand.
    ///
    /// The deterministic spawn seam: recording the work instead of launching a `Task` removes any
    /// executor race and any need to sleep, and means a revalidation cannot finish (or release its
    /// single-flight slot) until the test calls ``settle()``.
    private final class SpawnedTasks: Sendable {
        private let captured = Mutex<[@Sendable () async -> Void]>([])

        /// The middleware's spawn seam: records the background work without running it.
        var spawn: @Sendable (@escaping @Sendable () async -> Void) -> Void {
            { work in
                self.captured.withLock { $0.append(work) }
            }
        }

        /// How many background revalidations have been spawned (single-flight should keep this at one).
        var count: Int { captured.withLock(\.count) }

        /// Whether no background revalidation has been spawned.
        var isEmpty: Bool { captured.withLock(\.isEmpty) }

        /// Runs every captured revalidation to completion, so the cache reflects the refresh.
        func settle() async {
            for work in captured.withLock(\.self) {
                await work()
            }
        }

        deinit {
            // No teardown beyond ARC.
        }
    }

    /// A responder whose body is whatever the test currently sets — so a revalidation can return a new
    /// representation and the test can prove the stored entry was replaced.
    private final class MutableResponder: HTTPResponder {
        private let body: Mutex<String>
        private let cacheControl: String

        init(body: String, cacheControl: String) {
            self.body = Mutex(body)
            self.cacheControl = cacheControl
        }

        func setBody(_ value: String) { body.withLock { $0 = value } }

        func respond(to _: HTTPRequest, body _: [UInt8]) async -> ServerResponse {
            var fields = HTTPFields()
            _ = fields.setValue(cacheControl, for: .cacheControl)
            let head = HTTPResponse(status: .ok, headerFields: fields)
            return ServerResponse(head, body: Array(self.body.withLock(\.self).utf8))
        }

        deinit {
            // No teardown beyond ARC.
        }
    }

    private func get() -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/")
    }

    @Test("a stale entry inside the window is served stale now, then refreshed in the background")
    func servesStaleThenRefreshes() async {
        let clock = TestClock()
        let now: @Sendable () -> Int = { Int(clock.monotonicNanoseconds / 1_000_000_000) }
        let spawned = SpawnedTasks()
        let middleware = CacheMiddleware(now: now, spawn: spawned.spawn)
        let next = MutableResponder(
            body: "v1",
            cacheControl: "max-age=10, stale-while-revalidate=30"
        )

        // Prime the cache, then confirm a fresh hit.
        _ = await middleware.respond(to: get(), body: [], next: next)
        let fresh = await middleware.respond(to: get(), body: [], next: next)
        #expect(fresh.head.headerFields[.age] != nil)
        #expect(fresh.body == Array("v1".utf8))

        // Move past freshness (10s) but inside the 30s window; the origin now serves a new body.
        clock.advance(by: .seconds(15))
        next.setBody("v2")
        let stale = await middleware.respond(to: get(), body: [], next: next)
        #expect(stale.head.headerFields[.age] != nil)  // served from the cache, not the origin
        #expect(stale.body == Array("v1".utf8))  // the *stale* body, returned immediately
        #expect(spawned.count == 1)  // a background revalidation was triggered

        // Let the background revalidation finish, then the entry is fresh with the new body.
        await spawned.settle()
        let refreshed = await middleware.respond(to: get(), body: [], next: next)
        #expect(refreshed.head.headerFields[.age] != nil)
        #expect(refreshed.body == Array("v2".utf8))  // replaced by the revalidation
    }

    @Test("past the stale-while-revalidate window the stale entry is not served (RFC 5861 §3)")
    func outsideWindowNotServed() async {
        let clock = TestClock()
        let now: @Sendable () -> Int = { Int(clock.monotonicNanoseconds / 1_000_000_000) }
        let spawned = SpawnedTasks()
        let middleware = CacheMiddleware(now: now, spawn: spawned.spawn)
        let next = MutableResponder(
            body: "v1",
            cacheControl: "max-age=10, stale-while-revalidate=30"
        )

        _ = await middleware.respond(to: get(), body: [], next: next)
        clock.advance(by: .seconds(41))  // past freshness (10) + window (30)
        let response = await middleware.respond(to: get(), body: [], next: next)
        #expect(response.head.headerFields[.age] == nil)  // not served from the cache
        #expect(spawned.isEmpty)  // no background revalidation outside the window
    }

    @Test("a stored response without stale-while-revalidate is never served stale")
    func noDirectiveNeverServedStale() async {
        let clock = TestClock()
        let now: @Sendable () -> Int = { Int(clock.monotonicNanoseconds / 1_000_000_000) }
        let spawned = SpawnedTasks()
        let middleware = CacheMiddleware(now: now, spawn: spawned.spawn)
        let next = MutableResponder(body: "v1", cacheControl: "max-age=10")

        _ = await middleware.respond(to: get(), body: [], next: next)
        clock.advance(by: .seconds(11))  // stale, and no window at all
        let response = await middleware.respond(to: get(), body: [], next: next)
        #expect(response.head.headerFields[.age] == nil)
        #expect(spawned.isEmpty)
    }

    @Test("concurrent stale requests trigger a single background revalidation (single-flight)")
    func singleFlightRevalidation() async {
        let clock = TestClock()
        let now: @Sendable () -> Int = { Int(clock.monotonicNanoseconds / 1_000_000_000) }
        let spawned = SpawnedTasks()
        let middleware = CacheMiddleware(now: now, spawn: spawned.spawn)
        let next = MutableResponder(
            body: "v1",
            cacheControl: "max-age=10, stale-while-revalidate=30"
        )

        _ = await middleware.respond(to: get(), body: [], next: next)
        clock.advance(by: .seconds(15))  // stale but inside the window

        // Two stale hits before any revalidation settles: only the first claims the slot.
        let first = await middleware.respond(to: get(), body: [], next: next)
        let second = await middleware.respond(to: get(), body: [], next: next)
        #expect(first.head.headerFields[.age] != nil)
        #expect(second.head.headerFields[.age] != nil)
        // single-flight: the second stale hit did not spawn a second refresh.
        #expect(spawned.count == 1)
        await spawned.settle()
    }
}
