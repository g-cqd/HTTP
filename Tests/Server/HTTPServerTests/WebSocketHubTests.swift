//
//  WebSocketHubTests.swift
//  HTTPServerTests
//
//  Phase 2.7 — the WebSocketHub pub/sub primitive: a published message fans out to every subscriber of a
//  topic, other topics / non-subscribers receive nothing, and unsubscribe / remove stop delivery.
//

import Testing
import WebSocket

@testable import HTTPServer

@Suite("Phase 2.7 — WebSocket hub")
struct WebSocketHubTests {
    /// Collects the messages delivered to a sink (sinks run serially inside the hub actor, so a plain
    /// class suffices for these sequential tests).
    private final class Recorder: @unchecked Sendable {
        var messages: [WebSocketMessage] = []

        deinit {
            // No teardown beyond ARC.
        }
    }

    @Test("publishes a message to every subscriber of a topic")
    func fanOut() async {
        let hub = WebSocketHub()
        let a = Recorder()
        let b = Recorder()
        let tokenA = await hub.register { a.messages.append($0) }
        let tokenB = await hub.register { b.messages.append($0) }
        await hub.subscribe(tokenA, to: "room")
        await hub.subscribe(tokenB, to: "room")
        await hub.publish(.text("hi"), to: "room")
        #expect(a.messages == [.text("hi")])
        #expect(b.messages == [.text("hi")])
    }

    @Test("a different topic and a non-subscriber receive nothing")
    func isolation() async {
        let hub = WebSocketHub()
        let recorder = Recorder()
        let token = await hub.register { recorder.messages.append($0) }
        await hub.subscribe(token, to: "room")
        await hub.publish(.text("x"), to: "other")
        #expect(recorder.messages.isEmpty)
        #expect(await hub.subscriberCount(of: "room") == 1)
        #expect(await hub.subscriberCount(of: "other") == 0)
    }

    @Test("unsubscribe and remove both stop delivery")
    func unsubscribeAndRemove() async {
        let hub = WebSocketHub()
        let recorder = Recorder()
        let token = await hub.register { recorder.messages.append($0) }
        await hub.subscribe(token, to: "room")
        await hub.unsubscribe(token, from: "room")
        await hub.publish(.text("a"), to: "room")
        #expect(recorder.messages.isEmpty)

        await hub.subscribe(token, to: "room")
        await hub.remove(token)
        await hub.publish(.text("b"), to: "room")
        #expect(recorder.messages.isEmpty)
        #expect(await hub.subscriberCount(of: "room") == 0)
    }
}
