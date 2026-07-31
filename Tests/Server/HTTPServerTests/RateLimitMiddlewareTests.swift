//
//  RateLimitMiddlewareTests.swift
//  HTTPServerTests
//
//  Rate limiting (RFC 6585 §4): the per-client budget admits up to the limit per window and then
//  refuses with 429 + Retry-After, the window rolls over when the (deterministic) clock advances, and
//  distinct clients are independent. Time is the shared ``TestClock``, advanced explicitly — no
//  waiting.
//
//  The identity and bound tests are the audit-finding-9/10 regressions. A client is the *verified
//  peer*, never the `Host` header a caller writes for itself; a forwarded address is believed only
//  behind a trusted proxy (RFC 7239 §8.1); and the tracking table holds its cap against a flood of
//  *live* distinct clients, not merely against idle ones.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Middleware — rate limiting (RFC 6585 §4)")
struct RateLimitMiddlewareTests {
    private let ok = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }

    private func request(authority: String = "client-a") -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: authority, path: "/")
    }

    /// A context whose connection reports `peer` as the verified transport address.
    private func context(peer: String, port: UInt16 = 51_000) -> RequestContext {
        RequestContext(
            connection: RequestContext.Connection(
                peer: TransportAddress(host: peer, port: port)
            )
        )
    }

    @Test("admits up to the limit, then refuses with 429 + Retry-After")
    func limitThen429() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 2, per: .seconds(1), now: clock.nowProvider)
        let peer = context(peer: "203.0.113.1")
        let first = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        let second = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        let third = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        #expect(first.head.status == .ok)
        #expect(second.head.status == .ok)
        #expect(third.head.status == .tooManyRequests)
        #expect(third.head.headerFields[.retryAfter] == "1")
    }

    @Test("the budget resets when the window rolls over")
    func windowReset() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 1, per: .seconds(1), now: clock.nowProvider)
        let peer = context(peer: "203.0.113.1")
        let first = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        #expect(first.head.status == .ok)
        let refused = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        #expect(refused.head.status == .tooManyRequests)
        clock.advance(by: .seconds(1))
        let after = await limiter.respond(to: request(), body: [], context: peer, next: ok)
        #expect(after.head.status == .ok)
    }

    @Test("different clients have independent budgets")
    func perClient() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 1, per: .seconds(1), now: clock.nowProvider)
        let first = await limiter.respond(
            to: request(),
            body: [],
            context: context(peer: "203.0.113.1"),
            next: ok
        )
        let other = await limiter.respond(
            to: request(),
            body: [],
            context: context(peer: "203.0.113.2"),
            next: ok
        )
        let again = await limiter.respond(
            to: request(),
            body: [],
            context: context(peer: "203.0.113.1"),
            next: ok
        )
        #expect(first.head.status == .ok)
        #expect(other.head.status == .ok)
        #expect(again.head.status == .tooManyRequests)
    }

    @Test("the identity is the verified peer, not the Host header the caller writes")
    func identityIsThePeerNotTheHost() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 1, per: .seconds(60), now: clock.nowProvider)
        let peer = context(peer: "203.0.113.1")
        // One peer varying its own Host cannot mint a second budget — the pre-fix bypass.
        let first = await limiter.respond(
            to: request(authority: "a.example"),
            body: [],
            context: peer,
            next: ok
        )
        let disguised = await limiter.respond(
            to: request(authority: "b.example"),
            body: [],
            context: peer,
            next: ok
        )
        #expect(first.head.status == .ok)
        #expect(disguised.head.status == .tooManyRequests)
        #expect(limiter.trackedClients == 1)
    }

    @Test("clients sharing one Host header still have independent budgets")
    func sameHostDistinctPeers() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 1, per: .seconds(60), now: clock.nowProvider)
        let shared = request(authority: "api.example")
        // The pre-fix limiter pooled every caller of a virtual host into one budget, so a single
        // busy client starved all the others.
        for octet in 1 ... 20 {
            let response = await limiter.respond(
                to: shared,
                body: [],
                context: context(peer: "203.0.113.\(octet)"),
                next: ok
            )
            #expect(response.head.status == .ok)
        }
        #expect(limiter.trackedClients == 20)
    }

    @Test("a context with no peer shares one fail-closed budget")
    func syntheticContextSharesOneBudget() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 1, per: .seconds(60), now: clock.nowProvider)
        let first = await limiter.respond(to: request(authority: "a.example"), body: [], next: ok)
        let second = await limiter.respond(to: request(authority: "b.example"), body: [], next: ok)
        #expect(first.head.status == .ok)
        #expect(second.head.status == .tooManyRequests)
        #expect(limiter.trackedClients == 1)
    }

    @Test("IPv6 clients aggregate to a /64, so a subscriber cannot walk its own subnet")
    func ipv6AggregatesToAPrefix() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(limit: 2, per: .seconds(60), now: clock.nowProvider)
        var statuses: [HTTPStatus] = []
        for address in ["2001:db8:0:1::1", "2001:db8:0:1::2", "2001:db8:0:1:ffff::9"] {
            let response = await limiter.respond(
                to: request(),
                body: [],
                context: context(peer: address),
                next: ok
            )
            statuses.append(response.head.status)
        }
        #expect(statuses == [.ok, .ok, .tooManyRequests])
        #expect(limiter.trackedClients == 1)
        let neighbour = await limiter.respond(  // a different /64 is a different subscriber
            to: request(),
            body: [],
            context: context(peer: "2001:db8:0:2::1"),
            next: ok
        )
        #expect(neighbour.head.status == .ok)
        #expect(limiter.trackedClients == 2)
    }

    @Test("a /128 aggregation keeps every IPv6 address distinct")
    func ipv6PrefixIsConfigurable() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(
            limit: 1,
            per: .seconds(60),
            identity: .peerAddress(ipv6Prefix: 128),
            now: clock.nowProvider
        )
        let first = await limiter.respond(
            to: request(),
            body: [],
            context: context(peer: "2001:db8:0:1::1"),
            next: ok
        )
        let sibling = await limiter.respond(
            to: request(),
            body: [],
            context: context(peer: "2001:db8:0:1::2"),
            next: ok
        )
        #expect(first.head.status == .ok)
        #expect(sibling.head.status == .ok)
        #expect(limiter.trackedClients == 2)
    }

    @Test("a flood of live distinct clients never grows the table past maxTrackedClients")
    func floodCannotGrowTheTable() async {
        let clock = TestClock()
        // shards: 1 so admission order is deterministic; the sharded global bound is covered in
        // ShardedMutexTests.
        let limiter = RateLimitMiddleware(
            limit: 2,
            per: .seconds(3_600),
            maxTrackedClients: 4,
            shards: 1,
            now: clock.nowProvider
        )
        let tracked = (1 ... 4).map { context(peer: "203.0.113.\($0)") }
        for peer in tracked {
            let response = await limiter.respond(to: request(), body: [], context: peer, next: ok)
            #expect(response.head.status == .ok)
        }
        // A thousand further *live* clients inside the same window. Every one is refused, none
        // displaces a tracked client, and the table does not grow. The pre-fix prune dropped only
        // idle entries, so with nothing idle the map reached 1004 (CWE-400).
        for index in 0 ..< 1_000 {
            let newcomer = context(peer: "198.51.\(index / 254).\(index % 254 + 1)")
            let response = await limiter.respond(
                to: request(),
                body: [],
                context: newcomer,
                next: ok
            )
            #expect(response.head.status == .tooManyRequests)
        }
        #expect(limiter.trackedClients == 4)
        // The four tracked clients still hold exactly the budgets they had before the flood.
        for peer in tracked {
            let second = await limiter.respond(to: request(), body: [], context: peer, next: ok)
            #expect(second.head.status == .ok)
            let third = await limiter.respond(to: request(), body: [], context: peer, next: ok)
            #expect(third.head.status == .tooManyRequests)
        }
    }

    @Test("an idle client's slot is reclaimed once its window has elapsed")
    func idleSlotsAreReclaimed() async {
        let clock = TestClock()
        let limiter = RateLimitMiddleware(
            limit: 1,
            per: .seconds(1),
            maxTrackedClients: 2,
            shards: 1,
            now: clock.nowProvider
        )
        for octet in 1 ... 2 {
            let response = await limiter.respond(
                to: request(),
                body: [],
                context: context(peer: "203.0.113.\(octet)"),
                next: ok
            )
            #expect(response.head.status == .ok)
        }
        let full = await limiter.respond(
            to: request(),
            body: [],
            context: context(peer: "203.0.113.9"),
            next: ok
        )
        #expect(full.head.status == .tooManyRequests)
        clock.advance(by: .seconds(5))  // both tracked clients are now idle
        let admitted = await limiter.respond(
            to: request(),
            body: [],
            context: context(peer: "203.0.113.9"),
            next: ok
        )
        #expect(admitted.head.status == .ok)
        #expect(limiter.trackedClients <= 2)
    }
}
