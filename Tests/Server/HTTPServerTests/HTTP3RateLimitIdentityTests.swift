//
//  HTTP3RateLimitIdentityTests.swift
//  HTTPServerTests
//
//  Audit finding 10 for HTTP/3: ``RateLimitIdentity/peerAddress(ipv6Prefix:)`` is the default because
//  it keys a budget on the peer the server *verified* rather than on the attacker-controlled `Host`
//  header. That guarantee is only as good as ``QUICConnection/peer``, and while both QUIC backbones
//  reported the listener's own bind address it silently collapsed for h3: every HTTP/3 request, from
//  every client, drew on one shared budget (CWE-770, CWE-807).
//
//  These pin the h3 half of the chain — ``RequestContext/init(quic:request:)`` carrying the peer into
//  `context.connection.peer`, and the identity deriving a per-peer key from it — so a future change to
//  either end cannot quietly re-share the budget. The transport half (that `peer` is the real remote
//  address at all) is pinned by `QUICPeerAttributionTests`.
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTP/3 rate-limit identity — audit finding 10")
struct HTTP3RateLimitIdentityTests {
    private static let request = HTTPRequest(
        method: .get,
        scheme: "https",
        authority: "example.com",
        path: "/"
    )

    @Test(
        "an h3 request draws on a budget keyed by its own peer",
        arguments: [
            (peer: "198.51.100.4", key: "198.51.100.4"),
            (peer: "203.0.113.9", key: "203.0.113.9"),
            // IPv6 is aggregated to the /64 a single subscriber is routinely allocated (RFC 6177 §2),
            // exactly as it is for an h1/h2 peer — the point is that it is still *this* peer's /64.
            (peer: "2001:db8::5", key: "2001:db8::")
        ]
    )
    func keyIsDerivedFromTheQUICPeer(testCase: (peer: String, key: String)) {
        let context = RequestContext(
            quic: FakeQUICConnection(peer: TransportAddress(host: testCase.peer, port: 443)),
            request: Self.request
        )
        let key = RateLimitIdentity.peerAddress().key(for: Self.request, context: context)
        #expect(context.connection.peer?.host == testCase.peer)
        #expect(key == testCase.key)
    }

    @Test("two h3 peers do not share one budget")
    func distinctPeersGetDistinctBudgets() {
        let keys = ["198.51.100.4", "203.0.113.9"].map { Self.key(forPeer: $0) }
        #expect(Set(keys).count == 2)
    }

    @Test("an h3 peer the transport could not attribute falls into the shared fail-closed budget")
    func unattributablePeerSharesTheFailClosedBudget() {
        // The same `"-"` bucket a synthetic context with no peer at all lands in — one convention,
        // and deliberately *not* a fallback to the client-supplied authority.
        #expect(Self.key(forPeer: QUICPeer.unattributed.host) == RateLimitIdentity.unattributed)
    }

    /// The budget key an h3 request from `host` draws on.
    private static func key(forPeer host: String) -> String {
        let context = RequestContext(
            quic: FakeQUICConnection(peer: TransportAddress(host: host, port: 443)),
            request: request
        )
        return RateLimitIdentity.peerAddress().key(for: request, context: context)
    }
}
