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
    /// Collects the messages delivered to a sink (each test publishes from one task, so a plain class
    /// suffices — the hub itself makes no serialization promise across concurrent publishes).
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
        let tokenA = hub.register { a.messages.append($0) }
        let tokenB = hub.register { b.messages.append($0) }
        hub.subscribe(tokenA, to: "room")
        hub.subscribe(tokenB, to: "room")
        hub.publish(.text("hi"), to: "room")
        #expect(a.messages == [.text("hi")])
        #expect(b.messages == [.text("hi")])
    }

    @Test("a different topic and a non-subscriber receive nothing")
    func isolation() async {
        let hub = WebSocketHub()
        let recorder = Recorder()
        let token = hub.register { recorder.messages.append($0) }
        hub.subscribe(token, to: "room")
        hub.publish(.text("x"), to: "other")
        #expect(recorder.messages.isEmpty)
        #expect(hub.subscriberCount(of: "room") == 1)
        #expect(hub.subscriberCount(of: "other") == 0)
    }

    @Test("unsubscribe and remove both stop delivery")
    func unsubscribeAndRemove() async {
        let hub = WebSocketHub()
        let recorder = Recorder()
        let token = hub.register { recorder.messages.append($0) }
        hub.subscribe(token, to: "room")
        hub.unsubscribe(token, from: "room")
        hub.publish(.text("a"), to: "room")
        #expect(recorder.messages.isEmpty)

        hub.subscribe(token, to: "room")
        hub.remove(token)
        hub.publish(.text("b"), to: "room")
        #expect(recorder.messages.isEmpty)
        #expect(hub.subscriberCount(of: "room") == 0)
    }
}
