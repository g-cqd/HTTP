//
//  WebSocketBackpressureTests.swift
//  HTTPServerTests
//
//  The 2026-07-31 audit's finding 1 regression. The HTTP/1.1 WebSocket pump used to merge lossless
//  transport octets and droppable hub broadcasts into one `.bufferingNewest(256)` stream whose `yield`
//  result nobody inspected. Past 256 queued wakeups the *oldest* was silently evicted — and evicting an
//  inbound octet chunk desynchronizes the resumable frame parser, so the damage is corrupted framing,
//  not one lost message.
//
//  The two halves now travel separately: octets through a lossless `BoundedByteChannel` that parks the
//  reader (closing the peer's TCP window), broadcasts through a bounded `WebSocketBroadcastMailbox`
//  whose evictions are counted and turned into a `1008` close.
//
//  Parking itself is unit-tested in `BoundedByteChannelTests`; asserting it from out here would mean
//  polling for a plateau, which is inherently racy. These tests assert the observable contract instead:
//  nothing is lost, and a broadcast that *is* dropped ends the session visibly.
//

import HTTPCore
import HTTPTransport
internal import Synchronization
import Testing
import WebSocket

@testable import HTTPServer

@Suite("HTTPServer — WebSocket transport backpressure (audit F1)")
struct WebSocketBackpressureTests {
    /// The audit's required regression: block the pump, feed far more than the old 256-wakeup cap, and
    /// prove byte-for-byte delivery with no parser corruption.
    ///
    /// The handler cannot return until every staged chunk has been pulled off the wire, so the pump is
    /// provably blocked for the whole feed. Under the old `.bufferingNewest(256)` policy the first ~144
    /// chunks were evicted and the frame parser desynchronized; here all 400 messages arrive in order.
    @Test("no inbound chunk is lost when the handler blocks past the old 256-wakeup cap")
    func deliversEveryFrameWhileTheHandlerBlocks() async {
        let total = 400
        let received = Mutex<[String]>([])
        let connection = StagedChunkConnection(
            chunks: [Self.upgradeRequest] + (0 ..< total).map { Self.maskedTextFrame("m\($0)") }
        )
        let handler = ClosureWebSocketHandler { event in
            guard case .message(let opcode, let payload) = event, opcode == .text else {
                return []
            }
            let text = String(decoding: payload, as: Unicode.UTF8.self)
            // Park until the reader has drained the wire, so the pump is blocked for the whole feed.
            if text == "m0" {
                while await connection.handedOutCount() <= total {
                    await Task.yield()
                }
            }
            received.withLock { $0.append(text) }
            return []
        }
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: handler) }
        )
        await server.serve(connection)

        #expect(received.withLock(\.count) == total)
        #expect(received.withLock(\.self) == (0 ..< total).map { "m\($0)" })
    }

    /// Broadcasts may be dropped — but never silently.
    ///
    /// The handler publishes from inside `handle`, i.e. while the pump is inside its own `applyInbound`
    /// call, so every deposit lands against a blocked consumer. The mailbox evicts, counts, and the pump
    /// turns a non-zero count into a `1008` close (RFC 6455 §7.4.1). Closing the transport only *after*
    /// publishing keeps the wakeup order deterministic: the broadcast edge is raised strictly before the
    /// reader can yield its terminal ticket.
    @Test("a broadcast backlog is counted and closes the connection with 1008")
    func droppedBroadcastsClose1008() async {
        let hub = WebSocketHub()
        let connection = StagedChunkConnection(
            chunks: [Self.upgradeRequest, Self.maskedTextFrame("go")],
            parksAtEnd: true
        )
        let handler = ClosureWebSocketHandler { event in
            guard case .message = event else {
                return []
            }
            for index in 0 ..< 20 {
                await hub.publish(.text("b\(index)"), to: "room")  // capacity is 4 → 16 evicted
            }
            await connection.close()
            return []
        }
        var limits = HTTPLimits.default
        limits.maxQueuedBroadcasts = 4
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router {
                Route.webSocket("/chat", hub: hub, topic: "room", handler: handler)
            },
            limits: limits
        )
        await server.serve(connection)

        // A server Close frame is unmasked: 0x88, length, then the 2-octet status code. 1008 = 0x03F0.
        let sent = await connection.sentBytes()
        #expect(Self.containsSubsequence(sent, [0x88]))
        #expect(Self.containsSubsequence(sent, [0x03, 0xF0]))
    }

    /// A connection that keeps up must not be closed — the drop policy is a *backlog* policy.
    @Test("broadcasts within capacity are delivered without a close")
    func broadcastsWithinCapacityAreDelivered() async {
        let hub = WebSocketHub()
        let connection = StagedChunkConnection(
            chunks: [Self.upgradeRequest, Self.maskedTextFrame("go")],
            parksAtEnd: true
        )
        let handler = ClosureWebSocketHandler { event in
            guard case .message = event else {
                return []
            }
            await hub.publish(.text("hello"), to: "room")
            await connection.close()
            return []
        }
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router {
                Route.webSocket("/chat", hub: hub, topic: "room", handler: handler)
            }
        )
        await server.serve(connection)

        let sent = await connection.sentBytes()
        #expect(Self.containsSubsequence(sent, Array("hello".utf8)))
        #expect(!Self.containsSubsequence(sent, [0x03, 0xF0]))  // no 1008
    }

    /// The ticket invariant, end to end: a coalesced chunk must not strand an unrelated wakeup.
    ///
    /// The pump is the sole consumer of BOTH inbound octets and hub broadcasts. If a send that merely
    /// merged into the tail still yielded a ticket, the pump would take the merged item on the first
    /// ticket, park on the second with nothing to take, and never reach the `.broadcastReady` already
    /// queued behind it — so a broadcast to a live connection would simply never be written.
    ///
    /// The interleaving is forced rather than hoped for: the handler holds the pump until every staged
    /// chunk has been pulled off the wire, so the reader provably coalesces before the pump dequeues.
    @Test("a coalesced inbound chunk does not strand a queued broadcast")
    func coalescedChunkDoesNotStrandABroadcast() async {
        let hub = WebSocketHub()
        let staged: [[UInt8]] =
            [Self.upgradeRequest, Self.maskedTextFrame("go")]
            + (0 ..< 8).map { Self.maskedTextFrame("c\($0)") }
        let total = staged.count
        let connection = StagedChunkConnection(chunks: staged, parksAtEnd: true)

        let handler = ClosureWebSocketHandler { event in
            guard case .message(let opcode, let payload) = event, opcode == .text else {
                return []
            }
            let text = String(decoding: payload, as: Unicode.UTF8.self)
            if text == "go" {
                // Hold the pump until the reader has drained the wire, forcing the coalesce.
                while await connection.handedOutCount() < total {
                    await Task.yield()
                }
                await hub.publish(.text("ping"), to: "room")
            }
            if text == "c7" {
                // The last coalesced message: end the session so `serve` returns. The broadcast
                // wakeup was queued before the reader's terminal ticket, so it is still processed.
                await connection.close()
            }
            return []
        }
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router {
                Route.webSocket("/chat", hub: hub, topic: "room", handler: handler)
            }
        )
        await server.serve(connection)

        // The broadcast must have reached the wire as an outbound text frame.
        #expect(Self.containsSubsequence(await connection.sentBytes(), Array("ping".utf8)))
    }

    // MARK: Fixtures

    private static let upgradeRequest: [UInt8] = Array(
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

    private static func maskedTextFrame(_ text: String) -> [UInt8] {
        let payload = Array(text.utf8)
        let key: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        var frame: [UInt8] = [0x81, 0x80 | UInt8(payload.count)]
        frame += key
        for (index, byte) in payload.enumerated() { frame.append(byte ^ key[index & 0x3]) }
        return frame
    }

    private static func containsSubsequence(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard needle.count <= haystack.count else {
            return false
        }
        for start in 0 ... (haystack.count - needle.count)
        where Array(haystack[start ..< start + needle.count]) == needle {
            return true
        }
        return false
    }
}
