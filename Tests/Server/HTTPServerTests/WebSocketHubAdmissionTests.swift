//
//  WebSocketHubAdmissionTests.swift
//  HTTPServerTests
//
//  2026-07-31 audit, finding 16, at the server boundary. The hub now *reports* a refusal instead of
//  silently doing nothing, and this is the half that proves the server acts on the report: a
//  connection the hub cannot take is closed with `1013` Try Again Later (RFC 6455 §7.4.1) rather than
//  left upgraded on a hub-backed route where it would never hear a single broadcast.
//
//  1013, not 1011: nothing failed and nothing about the request was invalid — the server is simply at
//  a bounded capacity, and a client is right to come back.
//

import HTTPCore
import HTTPTransport
import Testing
import WebSocket

@testable import HTTPServer

/// A sink that discards: used only to fill the hub's budget before the server tries to join it.
private let discard: WebSocketHub.Sink = { _ in
    // Never published to.
}

private let upgradeRequest: [UInt8] = Array(
    [
        "GET /chat HTTP/1.1",
        "Host: example.com",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
        "",
        ""
    ]
    .joined(separator: "\r\n").utf8
)

/// Whether `haystack` holds `needle` contiguously.
private func containsSubsequence(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
    guard needle.count <= haystack.count else {
        return false
    }
    for start in 0 ... (haystack.count - needle.count)
    where Array(haystack[start ..< start + needle.count]) == needle {
        return true
    }
    return false
}

/// Serves one upgrade against `hub` and returns everything the server wrote.
private func serveUpgrade(against hub: WebSocketHub) async -> [UInt8] {
    let connection = StagedChunkConnection(chunks: [upgradeRequest], parksAtEnd: false)
    let server = HTTPServer(
        transport: FakeTransport(),
        responder: Router {
            Route.webSocket(
                "/chat",
                hub: hub,
                topic: "room",
                handler: ClosureWebSocketHandler { _ in [] }
            )
        }
    )
    await server.serve(connection)
    return await connection.sentBytes()
}

/// `0x88` is an unmasked server Close; `0x03F5` is 1013 in network order.
private let closeFrameOpcode: [UInt8] = [0x88]
private let tryAgainLaterCode: [UInt8] = [0x03, 0xF5]

@Test("a refused hub registration closes the upgraded socket with 1013")
func aRefusedRegistrationClosesWith1013() async {
    // One shard, budget of one, already spent — so the server's own registration is the one refused.
    let hub = WebSocketHub(limits: .init(maxSubscribers: 1), shards: 1)
    #expect(hub.register(discard) != nil)

    let sent = await serveUpgrade(against: hub)

    #expect(containsSubsequence(sent, Array("101 Switching Protocols".utf8)))
    #expect(containsSubsequence(sent, closeFrameOpcode))
    #expect(containsSubsequence(sent, tryAgainLaterCode))
}

@Test("a refused auto-subscribe closes the upgraded socket with 1013")
func aRefusedAutoSubscribeClosesWith1013() async throws {
    // Registration succeeds, then the topic budget — already spent on another name — refuses the
    // auto-subscribe. The connection must not be left half-joined.
    let hub = WebSocketHub(limits: .init(maxTopics: 1), shards: 1)
    let squatter = try #require(hub.register(discard))
    #expect(hub.subscribe(squatter, to: "someone-elses-topic") == .admitted)

    let sent = await serveUpgrade(against: hub)

    #expect(containsSubsequence(sent, closeFrameOpcode))
    #expect(containsSubsequence(sent, tryAgainLaterCode))
    // The refused connection's sink was withdrawn, not leaked: repeated refused upgrades must not
    // consume the subscriber budget, or the refusal itself becomes the exhaustion vector.
    #expect(hub.subscriberCount(of: "room") == 0)
    #expect(hub.register(discard) != nil)
}

@Test("a hub with room admits the connection and sends no close")
func aHubWithRoomAdmitsTheConnection() async {
    let hub = WebSocketHub(shards: 1)

    let sent = await serveUpgrade(against: hub)

    #expect(containsSubsequence(sent, Array("101 Switching Protocols".utf8)))
    #expect(!containsSubsequence(sent, tryAgainLaterCode))
}
