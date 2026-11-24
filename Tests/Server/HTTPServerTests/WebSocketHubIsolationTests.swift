//
//  WebSocketHubIsolationTests.swift
//  HTTPServerTests
//
//  2026-07-31 audit, finding 16 — a subscriber's sink is application code, and the hub must not run it
//  while holding the lock that every other topic needs. The pre-change hub invoked every sink while
//  holding actor isolation, so one connection whose send channel was wedged froze publication on every
//  unrelated topic in the process.
//
//  Both tests pin the hub to ONE shard. On a partitioned hub two arbitrary topic names would usually
//  land on different locks, and the test would then pass for a reason that has nothing to do with the
//  property under test.
//

import HTTPTestSupport
internal import Synchronization
import Testing
import WebSocket

@testable import HTTPServer

/// The deliver-outside-the-lock proof.
///
/// Sink A parks inside the hub on a gate; a publish to an unrelated topic B, issued from another task,
/// must still complete. Against a hub that delivers under the lock — the actor this replaced, and the
/// intermediate sharded version — B's publish blocks on the shard A is holding and this fails.
@Test("a blocking sink does not serialize an unrelated publish")
func blockingSinkDoesNotSerializeAnUnrelatedPublish() async throws {
    let hub = WebSocketHub(shards: 1)
    let release = ThreadGate()
    let parkedInside = AsyncEventProbe<Int>(label: "sinkA.parked")
    let deliveredToB = AsyncEventProbe<Int>(label: "sinkB.delivered")
    let parkingSink: WebSocketHub.Sink = { _ in
        parkedInside.record(1)
        release.waitUntilOpen()
    }
    let recordingSink: WebSocketHub.Sink = { _ in deliveredToB.record(1) }
    let slow = try #require(hub.register(parkingSink))
    let fast = try #require(hub.register(recordingSink))
    hub.subscribe(slow, to: "a")
    hub.subscribe(fast, to: "b")

    let blocked = Task.detached { hub.publish(.text("wedged"), to: "a") }
    _ = try await parkedInside.wait(forAtLeast: 1, timeout: .seconds(5))

    let unrelated = Task.detached { hub.publish(.text("through"), to: "b") }
    let arrived: Bool
    do {
        _ = try await deliveredToB.wait(forAtLeast: 1, timeout: .seconds(5))
        arrived = true
    }
    catch {
        arrived = false
    }

    release.open()  // before the expectation, so a failure still unwinds both tasks
    await blocked.value
    await unrelated.value
    #expect(arrived, "a publish to topic B was serialized behind a sink blocked on topic A")
}

/// The honest half of the same trade, asserted rather than merely documented.
///
/// Because the sink list is snapshotted before delivery, a subscriber that joins *during* a publish
/// does not receive that message. Subscribing from inside a sink also re-enters the hub while the
/// publish is in flight, which a hub delivering under a non-recursive lock cannot survive at all.
@Test("a subscriber joining during a publish is not delivered that message")
func aSubscriberJoiningDuringAPublishMissesIt() throws {
    let hub = WebSocketHub(shards: 1)
    let latecomerReceived = Mutex(0)
    let countingSink: WebSocketHub.Sink = { _ in latecomerReceived.withLock { $0 += 1 } }
    let latecomer = try #require(hub.register(countingSink))
    // `weak`, because a sink stored in the hub that strongly captured the hub would be a retain cycle
    // ARC cannot collect — the exact leak shape `BoundedLRU` exists to keep out of this package.
    let joiningSink: WebSocketHub.Sink = { [weak hub] _ in hub?.subscribe(latecomer, to: "room") }
    let joiner = try #require(hub.register(joiningSink))
    hub.subscribe(joiner, to: "room")

    // The sink subscribes the latecomer mid-flight; the snapshot was taken before delivery began, so
    // the latecomer is not in *this* fan-out.
    hub.publish(.text("first"), to: "room")
    #expect(latecomerReceived.withLock(\.self) == 0)

    hub.publish(.text("second"), to: "room")
    #expect(latecomerReceived.withLock(\.self) == 1)
}
