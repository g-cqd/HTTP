//
//  ForwardedAddressTests.swift
//  HTTPServerTests
//
//  ``ForwardedAddress`` and ``RateLimitIdentity/forwardedFor(trusting:ipv6Prefix:)``: a proxy chain is
//  believed only across a trust boundary (RFC 7239 §8.1). The whole matrix matters — a trusted peer
//  with a genuine chain, a trusted peer with a chain an attacker padded, an untrusted peer with any
//  chain at all — because getting the second or third case wrong hands every client the ability to
//  choose its own rate-limit identity (CWE-807, reliance on untrusted input in a security decision).
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

/// Peer → header value → the client address that must be derived, or `nil` to ignore the header.
private let forwardedVectors: [(peer: String, header: String, client: String?)] = [
    // A trusted proxy reporting a real client: believed.
    ("10.0.0.1", "203.0.113.7", "203.0.113.7"),
    ("127.0.0.1", "203.0.113.7", "203.0.113.7"),
    // A chain of trusted hops: the last untrusted address wins, reading right to left.
    ("10.0.0.1", "203.0.113.7, 10.0.0.9", "203.0.113.7"),
    ("10.0.0.1", "203.0.113.7, 10.0.0.9, 10.0.0.8", "203.0.113.7"),
    // A client padding the chain with a spoofed prefix: only the hop the trusted proxy actually
    // observed is taken, and the fabricated entries to its left are ignored.
    ("10.0.0.1", "198.51.100.1, 203.0.113.7", "203.0.113.7"),
    ("10.0.0.1", "1.1.1.1, 2.2.2.2, 203.0.113.7", "203.0.113.7"),
    // An untrusted peer: the header is attacker-authored end to end and is ignored outright.
    ("203.0.113.7", "10.0.0.5", nil),
    ("198.51.100.4", "198.51.100.9, 198.51.100.8", nil),
    // Every listed hop is trusted: the chain says nothing the peer did not already say.
    ("10.0.0.1", "10.0.0.9", nil),
    // Nothing parses, or the chain is deliberately opaque (RFC 7239 §6.3).
    ("10.0.0.1", "unknown", nil),
    ("10.0.0.1", "203.0.113.7, garbage", nil),
    ("10.0.0.1", "", nil),
    // Ports and bracketed IPv6 hosts are stripped (RFC 7239 §6).
    ("10.0.0.1", "203.0.113.7:4711", "203.0.113.7"),
    ("10.0.0.1", "[2001:db8::17]", "2001:db8::17"),
    ("10.0.0.1", "2001:db8::17", "2001:db8::17")
]

/// A `Forwarded` field value → the client address that must be derived, from a trusted `10.0.0.1`.
private let rfc7239Vectors: [(header: String, client: String?)] = [
    ("for=203.0.113.7", "203.0.113.7"),
    ("For=203.0.113.7", "203.0.113.7"),
    ("for=203.0.113.7;proto=https;by=10.0.0.1", "203.0.113.7"),
    ("by=10.0.0.1;proto=https;for=203.0.113.7", "203.0.113.7"),
    ("for=203.0.113.7, for=10.0.0.9", "203.0.113.7"),
    ("for=198.51.100.1, for=203.0.113.7", "203.0.113.7"),
    ("for=\"203.0.113.7:4711\"", "203.0.113.7"),
    ("for=\"[2001:db8:cafe::17]:4711\"", "2001:db8:cafe::17"),
    ("for=\"[2001:db8:cafe::17]\"", "2001:db8:cafe::17"),
    ("proto=https", nil),
    ("for=_hidden", nil),
    ("for=unknown", nil),
    ("for=203.0.113.7, for=_hidden", nil)
]

/// A trust boundary of the operator's own networks.
private let trustedProxies = IPPrefixSet.privateUse.union(.loopback)

/// Fields carrying `X-Forwarded-For: value`, or none when `value` is empty.
private func legacyFields(_ value: String) -> HTTPFields {
    var fields = HTTPFields()
    if !value.isEmpty {
        fields.append(value, for: .xForwardedFor)
    }
    return fields
}

@Test("X-Forwarded-For is believed only across a trust boundary", arguments: forwardedVectors)
func legacyForwardedForHonorsTrust(peer: String, header: String, client: String?) {
    guard let peerAddress = IPAddress(peer) else {
        Issue.record("\(peer) did not parse")
        return
    }
    let resolved = ForwardedAddress.client(
        legacyFields(header),
        peer: peerAddress,
        trusting: trustedProxies
    )
    #expect(resolved == client.flatMap { IPAddress($0) })
}

@Test("the RFC 7239 Forwarded field is parsed for its for= nodes", arguments: rfc7239Vectors)
func rfc7239ForwardedField(header: String, client: String?) {
    var fields = HTTPFields()
    fields.append(header, for: .forwarded)
    guard let peerAddress = IPAddress("10.0.0.1") else {
        Issue.record("the peer literal did not parse")
        return
    }
    let resolved = ForwardedAddress.client(fields, peer: peerAddress, trusting: trustedProxies)
    #expect(resolved == client.flatMap { IPAddress($0) })
}

@Test("Forwarded takes precedence over the legacy X-Forwarded-For")
func forwardedWinsOverLegacy() {
    var fields = HTTPFields()
    fields.append("for=203.0.113.7", for: .forwarded)
    fields.append("198.51.100.9", for: .xForwardedFor)
    guard let peerAddress = IPAddress("10.0.0.1") else {
        Issue.record("the peer literal did not parse")
        return
    }
    let resolved = ForwardedAddress.client(fields, peer: peerAddress, trusting: trustedProxies)
    #expect(resolved == IPAddress("203.0.113.7"))
}

@Test("an empty trust set ignores every forwarding header")
func emptyTrustSetIgnoresHeaders() {
    guard let peerAddress = IPAddress("10.0.0.1") else {
        Issue.record("the peer literal did not parse")
        return
    }
    let resolved = ForwardedAddress.client(
        legacyFields("203.0.113.7"),
        peer: peerAddress,
        trusting: .none
    )
    #expect(resolved == nil)
}

@Test("the limiter budgets the forwarded client behind a trusted proxy, and the peer otherwise")
func forwardedIdentityDrivesTheBudget() async {
    let ok = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
    let clock = TestClock()
    let limiter = RateLimitMiddleware(
        limit: 1,
        per: .seconds(60),
        identity: .forwardedFor(trusting: trustedProxies),
        now: clock.nowProvider
    )
    func request(forwardedFor client: String) -> HTTPRequest {
        var head = HTTPRequest(method: .get, scheme: "https", authority: "api.example", path: "/")
        head.headerFields.append(client, for: .xForwardedFor)
        return head
    }
    func context(peer: String) -> RequestContext {
        RequestContext(
            connection: RequestContext.Connection(peer: TransportAddress(host: peer, port: 443))
        )
    }
    // Behind the proxy, two forwarded clients get two budgets even though the peer is identical.
    let proxy = context(peer: "10.0.0.1")
    let one = request(forwardedFor: "203.0.113.1")
    let two = request(forwardedFor: "203.0.113.2")
    let first = await limiter.respond(to: one, body: [], context: proxy, next: ok)
    let other = await limiter.respond(to: two, body: [], context: proxy, next: ok)
    let again = await limiter.respond(to: one, body: [], context: proxy, next: ok)
    #expect(first.head.status == .ok)
    #expect(other.head.status == .ok)
    #expect(again.head.status == .tooManyRequests)
    // Direct from the internet, the header is worthless: one peer keeps one budget however it
    // spells X-Forwarded-For.
    let direct = context(peer: "198.51.100.9")
    let spoofOne = await limiter.respond(
        to: request(forwardedFor: "1.1.1.1"),
        body: [],
        context: direct,
        next: ok
    )
    let spoofTwo = await limiter.respond(
        to: request(forwardedFor: "2.2.2.2"),
        body: [],
        context: direct,
        next: ok
    )
    #expect(spoofOne.head.status == .ok)
    #expect(spoofTwo.head.status == .tooManyRequests)
}
