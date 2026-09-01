//
//  RateLimitIntervalValidationTests.swift
//  HTTPServerTests
//
//  Audit R5-VAL — a non-positive rate-limit window must not silently disable rate limiting.
//
//  ``RateLimitMiddleware``'s initializer already repairs every other knob it takes (`max(1, limit)`,
//  `max(1, maxTrackedClients)`, `max(1, shards)`, and a `Retry-After` floored at one second). The
//  window escaped, and it is the one value whose repair direction is not obvious: a `RollingWindow` of
//  zero (or of a negative duration) reports "rolled over" on *every* call, so the budget is zeroed
//  before each request and `count <= limit` is always true. A single mistyped configuration therefore
//  removed the control entirely — while the middleware went on reporting itself installed and healthy
//  (CWE-1284, improper validation of a specified quantity; the control it removes guards CWE-770).
//
//  These tests pin both halves: any non-positive window still limits, and any positive window — however
//  short — is left exactly as the operator asked for.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Rate limiting — a non-positive window still limits (R5-VAL)")
struct RateLimitIntervalValidationTests {
    private let ok = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }

    private static let nonPositive: [Duration] = [
        .zero,
        .nanoseconds(-1),
        .milliseconds(-1),
        .seconds(-1),
        .seconds(-86_400)
    ]

    private func context(peer: String) -> RequestContext {
        RequestContext(
            connection: RequestContext.Connection(
                peer: TransportAddress(host: peer, port: 51_000)
            )
        )
    }

    private func request() -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/")
    }

    @Test("a non-positive window still refuses past the limit", arguments: nonPositive)
    func nonPositiveWindowStillLimits(_ interval: Duration) async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 2, per: interval, now: clock.nowProvider)
        let peer = context(peer: "203.0.113.1")
        let first = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        let second = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        let third = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        #expect(first.head.status == .ok)
        #expect(second.head.status == .ok)
        #expect(third.head.status == .tooManyRequests)
    }

    @Test("the substituted window is a real window that still rolls over", arguments: nonPositive)
    func substitutedWindowRollsOver(_ interval: Duration) async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 1, per: interval, now: clock.nowProvider)
        let peer = context(peer: "203.0.113.2")
        _ = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        let refused = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        #expect(refused.head.status == .tooManyRequests)
        clock.advance(by: RateLimitMiddleware.substitutedInterval)
        let after = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        #expect(after.head.status == .ok)
    }

    @Test("the Retry-After advertised matches the window actually enforced", arguments: nonPositive)
    func retryAfterMatchesTheEnforcedWindow(_ interval: Duration) async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 1, per: interval, now: clock.nowProvider)
        let peer = context(peer: "203.0.113.3")
        _ = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        let refused = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        let seconds = RateLimitMiddleware.substitutedInterval.components.seconds
        #expect(refused.head.headerFields[.retryAfter] == String(seconds))
    }

    @Test("a positive window is honored exactly, never widened to the substitute")
    func shortPositiveWindowIsUntouched() async {
        let clock = TestClock()
        // 100 ms is a perfectly sane window and must survive untouched — the repair applies only to
        // the incoherent case, so an operator who asked for a sub-second budget still gets one.
        let limiter = RateLimitMiddleware(limit: 1, per: .milliseconds(100), now: clock.nowProvider)
        let peer = context(peer: "203.0.113.4")
        _ = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        let refused = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        #expect(refused.head.status == .tooManyRequests)
        clock.advance(by: .milliseconds(100))
        let after = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        #expect(after.head.status == .ok)
    }
}
