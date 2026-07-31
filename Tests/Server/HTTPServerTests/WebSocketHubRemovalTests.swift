//
//  WebSocketHubRemovalTests.swift
//  HTTPServerTests
//
//  2026-07-31 audit, finding 16 — disconnect must cost what the *connection* held, not what the *hub*
//  holds. The pre-change hub scanned `Array(topics.keys)` on every `remove`, which measured 0.86 ms at
//  1 000 topics, 7.5 ms at 10 000 and 70 ms at 100 000: exactly linear in the hub's topic space, and
//  therefore a CPU-exhaustion amplifier reachable by disconnecting (CWE-407).
//
//  The cost claim is asserted structurally rather than by wall clock: `removalProbeCount` counts the
//  topic-map entries a removal examined, so "proportional to this connection's own subscriptions" is a
//  deterministic equality instead of a timing threshold that flakes on a loaded CI machine.
//

import Testing
import WebSocket

@testable import HTTPServer

/// A sink that discards every message: this file asserts on index shape, never on delivery.
private let discard: WebSocketHub.Sink = { _ in
    // Delivery is covered by `WebSocketHubTests`; here only the bookkeeping matters.
}

/// Bounds wide enough to be out of the way: this file is about removal cost, not about admission
/// (which `WebSocketHubCardinalityTests` covers).
private let unbounded = WebSocketHub.Limits(
    maxSubscribers: 1 << 20,
    maxTopics: 1 << 20,
    maxSubscriptionsPerConnection: 1 << 20
)

@Test("removing a connection drops only its own subscriptions")
func removalDropsOnlyItsOwnSubscriptions() throws {
    let hub = WebSocketHub(limits: unbounded)
    let leaver = try #require(hub.register(discard))
    let stayer = try #require(hub.register(discard))
    let topics = (0 ..< 1_000).map { "topic-\($0)" }
    for topic in topics {
        hub.subscribe(stayer, to: topic)
    }
    let held = ["topic-7", "topic-500", "topic-999"]
    for topic in held {
        hub.subscribe(leaver, to: topic)
    }
    #expect(hub.topicCount == topics.count)

    hub.remove(leaver)

    // The three the leaver shared drop back to one subscriber; the other 997 are untouched. Asserted
    // over every topic, not a sample: a scan-and-mutate bug would show up on an arbitrary one.
    for topic in topics {
        #expect(hub.subscriberCount(of: topic) == 1)
    }
    #expect(hub.topicCount == topics.count)  // the stayer keeps every topic alive
}

/// Removal cost is proportional to the leaving connection's subscriptions, not to the hub's size.
///
/// Parameterized over the hub's topic space precisely because the answer must not move with it: the
/// pre-change hub probed `topicCount` entries here, so this would have read 100 / 10 000 / 100 000.
@Test(
    "removal cost does not scale with topic count",
    arguments: [100, 10_000, 100_000]
)
func removalCostIsIndependentOfTopicCount(topicCount: Int) throws {
    let hub = WebSocketHub(limits: unbounded)
    let crowd = try #require(hub.register(discard))
    for index in 0 ..< topicCount {
        hub.subscribe(crowd, to: "t\(index)")
    }
    let leaver = try #require(hub.register(discard))
    for topic in ["t0", "t1", "t2"] {
        hub.subscribe(leaver, to: topic)
    }
    let before = hub.removalProbeCount

    hub.remove(leaver)

    #expect(hub.removalProbeCount - before == 3)
}

/// The reverse index must be kept in step by `unsubscribe` too, or a later `remove` under-probes.
@Test("unsubscribe retires the reverse-index entry as well as the membership")
func unsubscribeUpdatesBothIndexes() throws {
    let hub = WebSocketHub(limits: unbounded)
    let token = try #require(hub.register(discard))
    hub.subscribe(token, to: "a")
    hub.subscribe(token, to: "b")
    hub.unsubscribe(token, from: "a")
    #expect(hub.subscriberCount(of: "a") == 0)
    #expect(hub.topicCount == 1)  // "a" retired once empty
    let before = hub.removalProbeCount

    hub.remove(token)

    #expect(hub.removalProbeCount - before == 1)  // only "b" remained held
    #expect(hub.topicCount == 0)
}
