//
//  RateLimitMiddlewareTests.swift
//  HTTPServerTests
//
//  Rate limiting (RFC 6585 §4): the per-client budget admits up to the limit per window and then
//  refuses with 429 + Retry-After, the window rolls over when the (deterministic) clock advances, and
//  distinct clients are independent. Time is the shared ``TestClock``, advanced explicitly — no waiting.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTPServer

@Suite("Middleware — rate limiting (RFC 6585 §4)")
struct RateLimitMiddlewareTests {
    private let ok = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }

    private func request(authority: String = "client-a") -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: authority, path: "/")
    }

    @Test("admits up to the limit, then refuses with 429 + Retry-After")
    func limitThen429() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 2, per: .seconds(1), now: clock.nowProvider)
        let first = await limiter.respond(to: request(), body: [], next: ok)
        let second = await limiter.respond(to: request(), body: [], next: ok)
        let third = await limiter.respond(to: request(), body: [], next: ok)
        #expect(first.head.status == .ok)
        #expect(second.head.status == .ok)
        #expect(third.head.status == .tooManyRequests)
        #expect(third.head.headerFields[.retryAfter] == "1")
    }

    @Test("the budget resets when the window rolls over")
    func windowReset() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 1, per: .seconds(1), now: clock.nowProvider)
        #expect(await limiter.respond(to: request(), body: [], next: ok).head.status == .ok)
        let refused = await limiter.respond(to: request(), body: [], next: ok)
        #expect(refused.head.status == .tooManyRequests)
        clock.advance(by: .seconds(1))
        #expect(await limiter.respond(to: request(), body: [], next: ok).head.status == .ok)
    }

    @Test("different clients have independent budgets")
    func perClient() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 1, per: .seconds(1), now: clock.nowProvider)
        let a = await limiter.respond(to: request(authority: "a"), body: [], next: ok)
        let b = await limiter.respond(to: request(authority: "b"), body: [], next: ok)
        let aAgain = await limiter.respond(to: request(authority: "a"), body: [], next: ok)
        #expect(a.head.status == .ok)
        #expect(b.head.status == .ok)
        #expect(aAgain.head.status == .tooManyRequests)
    }
}
