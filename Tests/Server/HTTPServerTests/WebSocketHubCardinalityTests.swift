//
//  WebSocketHubCardinalityTests.swift
//  HTTPServerTests
//
//  2026-07-31 audit, finding 16 — the hub accepted any number of connections, any number of topics,
//  any number of subscriptions per connection, and any topic name at all. Every one of those is
//  attacker-chosen on an endpoint that lets a client name its own room, so every one of them is an
//  allocation-without-limits door (CWE-770).
//
//  Each bound is asserted through the *specific* refusal it produces, not merely "something went
//  wrong": a caller that cannot tell "your token is stale" from "the server is full" cannot pick a
//  correct close code, and RFC 6455 §7.4.1 has different codes for those.
//
//  Every hub here is pinned to ONE shard. Budgets are divided across shards by floor (the
//  `SharedBoundedLRU` discipline, so the partitioned total can never exceed the requested cap), which
//  means a 16-shard hub refuses when *a shard* fills — correct, but not a fixed number.
//

import Testing
import WebSocket

@testable import HTTPServer

/// A sink that discards every message: this file asserts on admission, never on delivery.
private let discard: WebSocketHub.Sink = { _ in
    // Delivery is covered by `WebSocketHubTests`.
}

@Test(
    "registration is refused once the subscriber budget is exhausted",
    arguments: [1, 2, 8]
)
func registrationIsRefusedAtTheSubscriberBudget(maxSubscribers: Int) {
    let hub = WebSocketHub(limits: .init(maxSubscribers: maxSubscribers), shards: 1)
    for _ in 0 ..< maxSubscribers {
        #expect(hub.register(discard) != nil)
    }
    // A refusal, not an eviction: displacing a tracked connection would let an attacker knock any
    // victim off the hub on demand, which is worse than the flood it bounds (CWE-770).
    #expect(hub.register(discard) == nil)
}

@Test(
    "subscription is refused once this connection holds its topic budget",
    arguments: [1, 2, 8]
)
func subscriptionIsRefusedAtThePerConnectionBudget(maxPerConnection: Int) throws {
    let limits = WebSocketHub.Limits(maxSubscriptionsPerConnection: maxPerConnection)
    let hub = WebSocketHub(limits: limits, shards: 1)
    let token = try #require(hub.register(discard))
    for index in 0 ..< maxPerConnection {
        #expect(hub.subscribe(token, to: "t\(index)") == .admitted)
    }
    #expect(hub.subscribe(token, to: "overflow") == .refused(.connectionSubscriptionLimit))
    // Re-subscribing to a topic already held is idempotent, not an overflow — otherwise a reconnect
    // to the same room would be refused by a budget it does not actually consume.
    #expect(hub.subscribe(token, to: "t0") == .admitted)
    #expect(hub.subscriberCount(of: "overflow") == 0)
}

@Test(
    "subscription is refused once the hub holds its topic budget",
    arguments: [1, 2, 8]
)
func subscriptionIsRefusedAtTheTopicBudget(maxTopics: Int) throws {
    let limits = WebSocketHub.Limits(maxTopics: maxTopics, maxSubscriptionsPerConnection: .max)
    let hub = WebSocketHub(limits: limits, shards: 1)
    let token = try #require(hub.register(discard))
    for index in 0 ..< maxTopics {
        #expect(hub.subscribe(token, to: "t\(index)") == .admitted)
    }
    #expect(hub.subscribe(token, to: "one-too-many") == .refused(.topicLimit))
    #expect(hub.topicCount == maxTopics)
    // An existing topic is still joinable at the budget — the bound is on distinct names, not on
    // subscriptions, so a full hub must not stop its live rooms accepting members.
    let second = try #require(hub.register(discard))
    #expect(hub.subscribe(second, to: "t0") == .admitted)
}

@Test("a subscription against an unregistered token is refused as such")
func subscriptionWithAnUnknownTokenIsRefused() throws {
    let hub = WebSocketHub(shards: 1)
    #expect(hub.subscribe(999, to: "room") == .refused(.unknownToken))
    let token = try #require(hub.register(discard))
    hub.remove(token)
    #expect(hub.subscribe(token, to: "room") == .refused(.unknownToken))
    #expect(hub.topicCount == 0)
}

/// Topic names are VCHAR-only (`%x21-7E`, RFC 5234 §B.1) and length-bounded.
///
/// A control octet in an attacker-chosen name reaches logs and metric dimensions verbatim (CWE-117),
/// and an unbounded name is retained per topic and compared on every publish.
@Test(
    "an oversized or non-visible-ASCII topic name is refused",
    arguments: [
        ("", WebSocketHub.Refusal.emptyTopicName),
        (String(repeating: "r", count: 33), .topicNameTooLong),
        ("room chat", .topicNameNotVisibleASCII),  // 0x20 SP is not VCHAR
        ("room\u{7F}", .topicNameNotVisibleASCII),  // DEL
        ("room\r\nX-Injected: 1", .topicNameNotVisibleASCII),  // CWE-117 log injection
        ("röom", .topicNameNotVisibleASCII)  // non-ASCII UTF-8
    ]
)
func aMalformedTopicNameIsRefused(topic: String, expected: WebSocketHub.Refusal) throws {
    let hub = WebSocketHub(limits: .init(maxTopicNameLength: 32), shards: 1)
    let token = try #require(hub.register(discard))
    #expect(hub.subscribe(token, to: topic) == .refused(expected))
    #expect(hub.topicCount == 0)  // nothing was allocated for a name that was never admitted
    // The name is validated before any budget is touched, so a refused name leaves the connection's
    // own subscription budget untouched too.
    #expect(hub.subscribe(token, to: String(repeating: "r", count: 32)) == .admitted)
}
