//
//  HTTPServerWebSocketTests.swift
//  HTTPServerTests
//
//  Drives the server's WebSocket integration over an in-memory FakeConnection (RFC 6455 §4): an
//  HTTP/1.1 Upgrade request plus a masked text frame go in; a 101 Switching Protocols response with
//  the correct Sec-WebSocket-Accept and an echoed text frame must come back — proving the handshake
//  and the connection driver without a socket.
//

import HTTPCore
import HTTPTransport
internal import Synchronization
import Testing
import WebSocket

@testable import HTTPServer

@Suite("HTTPServer — WebSocket (RFC 6455) integration")
struct HTTPServerWebSocketTests {
    @Test("upgrades an HTTP/1.1 request and echoes a text message end-to-end")
    func upgradesAndEchoes() async {
        let echo = ClosureWebSocketHandler { event in
            guard case .message(let opcode, let payload) = event, opcode == .text else {
                return []
            }
            return [.sendText(String(decoding: payload, as: Unicode.UTF8.self))]
        }

        var wire = upgradeRequest()
        wire += maskedTextFrame("hi")  // a frame the client sends right after the request
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: wire)
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: echo) }
        )
        await server.serve(connection)

        let sent = await connection.sentBytes()
        let head = String(decoding: sent, as: Unicode.UTF8.self)
        #expect(head.hasPrefix("HTTP/1.1 101 Switching Protocols\r\n"))
        #expect(head.contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"))
        #expect(!head.contains("content-length"))  // a 101 carries no content (RFC 9110 §6.4.1)
        // The echoed server frame is an unmasked text "hi": 0x81, len 2, 'h', 'i'.
        #expect(containsSubsequence(sent, [0x81, 0x02, 0x68, 0x69]))
    }

    @Test("rejects a malformed upgrade with 426 and does not echo (RFC 6455 §4.4)")
    func rejectsBadVersion() async {
        let echo = ClosureWebSocketHandler { _ in [] }
        var wire: [UInt8] = []
        wire += Array("GET /chat HTTP/1.1\r\n".utf8)
        wire += Array("Host: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n".utf8)
        wire += Array("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n".utf8)
        wire += Array("Sec-WebSocket-Version: 8\r\n\r\n".utf8)  // unsupported version
        let connection = FakeConnection(id: TransportConnectionID(2), inbound: wire)
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: echo) }
        )
        await server.serve(connection)

        let head = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(head.hasPrefix("HTTP/1.1 426 "))
    }

    @Test("rejects a cross-site Origin with 403 and does not upgrade (CSWSH, RFC 6455 §10.2)")
    func rejectsDisallowedOrigin() async {
        let handler = ClosureWebSocketHandler(
            isOriginAllowed: { $0 == "https://good.example" }, handle: { _ in [] }
        )
        let connection = FakeConnection(
            id: TransportConnectionID(3), inbound: upgradeRequest(origin: "https://evil.example")
        )
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: handler) }
        )
        await server.serve(connection)

        let head = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(head.hasPrefix("HTTP/1.1 403 "))
        #expect(!head.contains("101 Switching Protocols"))
    }

    @Test("accepts an allowlisted Origin and upgrades (RFC 6455 §4.2)")
    func acceptsAllowlistedOrigin() async {
        let handler = ClosureWebSocketHandler(
            isOriginAllowed: { $0 == "https://good.example" }, handle: { _ in [] }
        )
        let connection = FakeConnection(
            id: TransportConnectionID(4), inbound: upgradeRequest(origin: "https://good.example")
        )
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: handler) }
        )
        await server.serve(connection)

        let head = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(head.hasPrefix("HTTP/1.1 101 Switching Protocols\r\n"))
    }

    @Test("default Origin policy: reject browser origin, admit no-Origin client (CSWSH)")
    func defaultOriginPolicyIsSecureByDefault() async {
        // A default handler (no isOriginAllowed override) must reject any browser-supplied Origin…
        let echo = ClosureWebSocketHandler { _ in [] }
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: echo) }
        )
        let browser = FakeConnection(
            id: TransportConnectionID(5), inbound: upgradeRequest(origin: "https://evil.example")
        )
        await server.serve(browser)
        let rejected = String(decoding: await browser.sentBytes(), as: Unicode.UTF8.self)
        #expect(rejected.hasPrefix("HTTP/1.1 403 "))
        #expect(!rejected.contains("101 Switching Protocols"))

        // …but still admit a non-browser client that sends no Origin.
        let nonBrowser = FakeConnection(id: TransportConnectionID(6), inbound: upgradeRequest())
        await server.serve(nonBrowser)
        let admitted = String(decoding: await nonBrowser.sentBytes(), as: Unicode.UTF8.self)
        #expect(admitted.hasPrefix("HTTP/1.1 101 Switching Protocols\r\n"))
    }

    @Test("a non-upgrade GET to a WebSocket path gets 426, while other routes still serve")
    func nonUpgradeGetToWebSocketPathGets426() async {
        let echo = ClosureWebSocketHandler { _ in [] }
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router {
                Route.get("/") { _, _, _ in .text("root") }
                Route.webSocket("/chat", handler: echo)
            }
        )
        // A plain GET (no Upgrade) to the WebSocket path falls through to the route's 426 fallback…
        let chat = FakeConnection(id: TransportConnectionID(7), inbound: plainGet("/chat"))
        await server.serve(chat)
        let chatHead = String(decoding: await chat.sentBytes(), as: Unicode.UTF8.self)
        #expect(chatHead.hasPrefix("HTTP/1.1 426 "))
        #expect(chatHead.lowercased().contains("upgrade: websocket\r\n"))  // RFC 9110 §7.8
        // …while an ordinary route on the same server still answers normally.
        let root = FakeConnection(id: TransportConnectionID(8), inbound: plainGet("/"))
        await server.serve(root)
        let rootHead = String(decoding: await root.sentBytes(), as: Unicode.UTF8.self)
        #expect(rootHead.hasPrefix("HTTP/1.1 200 "))
    }

    @Test("a POST to a WebSocket path is 405 — the route is declared GET (coexistence)")
    func postToWebSocketPathIsMethodNotAllowed() async {
        let echo = ClosureWebSocketHandler { _ in [] }
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: echo) }
        )
        let connection = FakeConnection(
            id: TransportConnectionID(9),
            inbound: Array("POST /chat HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n".utf8)
        )
        await server.serve(connection)
        let head = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(head.hasPrefix("HTTP/1.1 405 "))
    }

    @Test("a WebSocket route behind a middleware chain still upgrades (the resolver forwards)")
    func webSocketRouteBehindMiddlewareChainUpgrades() async {
        let echo = ClosureWebSocketHandler { event in
            guard case .message(let opcode, let payload) = event, opcode == .text else {
                return []
            }
            return [.sendText(String(decoding: payload, as: Unicode.UTF8.self))]
        }
        let responder = MiddlewareChain(
            [PassThrough()],
            terminatingAt: Router { Route.webSocket("/chat", handler: echo) }
        )
        var wire = upgradeRequest()
        wire += maskedTextFrame("hi")
        let connection = FakeConnection(id: TransportConnectionID(10), inbound: wire)
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)

        let sent = await connection.sentBytes()
        #expect(String(decoding: sent, as: Unicode.UTF8.self).hasPrefix("HTTP/1.1 101 "))
        #expect(containsSubsequence(sent, [0x81, 0x02, 0x68, 0x69]))  // echoed unmasked "hi"
    }

    @Test("maxWebSocketMessageSize decouples the WS cap from maxBodySize (independent raise)")
    func webSocketCapIndependentOfBodyLimit() async {
        let echo = ClosureWebSocketHandler { event in
            guard case .message(let opcode, let payload) = event, opcode == .text else {
                return []
            }
            return [.sendText(String(decoding: payload, as: Unicode.UTF8.self))]
        }
        // 100 octets: over the 16-octet HTTP body cap, under the 200-octet WebSocket message cap —
        // before the knob, the message cap silently followed maxBodySize and this echo failed (1009).
        let message = String(repeating: "m", count: 100)
        var wire = upgradeRequest()
        wire += maskedTextFrame(message)
        let connection = FakeConnection(id: TransportConnectionID(12), inbound: wire)
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: echo) },
            limits: HTTPLimits(maxBodySize: 16, maxWebSocketMessageSize: 200)
        )
        await server.serve(connection)
        let sent = await connection.sentBytes()
        #expect(String(decoding: sent, as: Unicode.UTF8.self).hasPrefix("HTTP/1.1 101 "))
        // The echoed server frame: unmasked text, single-byte length 100, then the payload.
        #expect(containsSubsequence(sent, [0x81, 0x64] + Array(message.utf8)))
    }

    @Test("an over-cap message closes 1009 under a small WS cap alone (RFC 6455 §7.4.1)")
    func webSocketCapEnforcedIndependently() async {
        let echo = ClosureWebSocketHandler { _ in [] }
        var wire = upgradeRequest()
        // 7 octets > the 4-octet WS cap; maxBodySize stays untouched.
        wire += maskedTextFrame("too big")
        let connection = FakeConnection(id: TransportConnectionID(13), inbound: wire)
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: echo) },
            limits: HTTPLimits(maxWebSocketMessageSize: 4)
        )
        await server.serve(connection)
        let sent = await connection.sentBytes()
        #expect(String(decoding: sent, as: Unicode.UTF8.self).hasPrefix("HTTP/1.1 101 "))
        // Close frame, code 1009 (message too big): FIN|Close, length 2, 0x03F1.
        #expect(containsSubsequence(sent, [0x88, 0x02, 0x03, 0xF1]))
    }

    @Test("a hub-backed WebSocket route upgrades (the connection is hub-driven) (Phase 2.7)")
    func hubBackedRouteUpgrades() async {
        let hub = WebSocketHub()
        let echo = ClosureWebSocketHandler { _ in [] }
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", hub: hub, topic: "chat", handler: echo) }
        )
        let connection = FakeConnection(id: TransportConnectionID(11), inbound: upgradeRequest())
        await server.serve(connection)
        // The upgrade completes on the hub-driven path; live fan-out is covered by `WebSocketHubTests`
        // (a self-broadcast over a one-shot FakeConnection races the immediate EOF, so it is unit-tested
        // on the hub rather than asserted here).
        let head = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(head.hasPrefix("HTTP/1.1 101 Switching Protocols\r\n"))
    }

    @Test("onOpen speaks first and onClose fires exactly once (lifecycle hooks)")
    func lifecycleHooksFire() async {
        let closes = CloseCounter()
        var wire = upgradeRequest()
        wire += maskedTextFrame("hi")
        let connection = FakeConnection(id: TransportConnectionID(14), inbound: wire)
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: HookedEcho(closes: closes)) }
        )
        await server.serve(connection)

        let sent = await connection.sentBytes()
        #expect(String(decoding: sent, as: Unicode.UTF8.self).hasPrefix("HTTP/1.1 101 "))
        // The onOpen greeting ("welcome", an unmasked 7-octet text frame) must precede the echo of
        // the client's first frame — the handler spoke FIRST.
        let welcome: [UInt8] = [0x81, 0x07] + Array("welcome".utf8)
        let echo: [UInt8] = [0x81, 0x02] + Array("hi".utf8)
        let welcomeAt = firstIndex(of: welcome, in: sent)
        let echoAt = firstIndex(of: echo, in: sent)
        #expect(welcomeAt != nil)
        #expect(echoAt != nil)
        if let welcomeAt, let echoAt {
            #expect(welcomeAt < echoAt)
        }
        // The session ended (EOF after the client's frame): onClose fired exactly once.
        #expect(closes.count == 1)
    }

    // MARK: Fixtures

    /// Counts ``WebSocketHandler/onClose()`` invocations (exactly-once assertion).
    private final class CloseCounter: Sendable {
        private let closes = Mutex(0)

        var count: Int { closes.withLock(\.self) }

        func bump() { closes.withLock { $0 += 1 } }

        deinit {
            // No teardown beyond ARC.
        }
    }

    /// An echo handler with lifecycle hooks: greets on open, counts its close.
    private struct HookedEcho: WebSocketHandler {
        let closes: CloseCounter

        func handle(_ event: WebSocketConnection.Event) async -> [WebSocketAction] {
            guard case .message(let opcode, let payload) = event, opcode == .text else {
                return []
            }
            return [.sendText(String(decoding: payload, as: Unicode.UTF8.self))]
        }

        func onOpen() async -> [WebSocketAction] {
            [.sendText("welcome")]
        }

        func onClose() async {
            closes.bump()
        }
    }

    /// The start index of `needle` in `haystack`, or nil.
    private func firstIndex(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard needle.count <= haystack.count, !needle.isEmpty else {
            return nil
        }
        for start in 0 ... (haystack.count - needle.count)
        where Array(haystack[start ..< start + needle.count]) == needle {
            return start
        }
        return nil
    }

    /// A no-op middleware that forwards to `next` unchanged — proves the resolver seam threads through a
    /// ``MiddlewareChain`` to the inner ``Router`` (the WebSocket upgrade is decided at the head).
    private struct PassThrough: HTTPMiddleware {
        func respond(
            to request: HTTPRequest,
            body: RequestBody,
            context: RequestContext,
            next: any HTTPResponder
        ) async -> ServerResponse {
            await next.respond(to: request, body: body, context: context)
        }
    }

    private func plainGet(_ path: String) -> [UInt8] {
        Array("GET \(path) HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
    }

    private func upgradeRequest(origin: String? = nil) -> [UInt8] {
        var wire: [UInt8] = []
        wire += Array("GET /chat HTTP/1.1\r\n".utf8)
        wire += Array("Host: example.com\r\n".utf8)
        wire += Array("Upgrade: websocket\r\n".utf8)
        wire += Array("Connection: Upgrade\r\n".utf8)
        wire += Array("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n".utf8)
        wire += Array("Sec-WebSocket-Version: 13\r\n".utf8)
        if let origin { wire += Array("Origin: \(origin)\r\n".utf8) }
        wire += Array("\r\n".utf8)
        return wire
    }

    private func maskedTextFrame(_ text: String) -> [UInt8] {
        let payload = Array(text.utf8)
        let key: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        var frame: [UInt8] = [0x81, 0x80 | UInt8(payload.count)]
        frame += key
        for (index, byte) in payload.enumerated() { frame.append(byte ^ key[index & 0x3]) }
        return frame
    }

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
}
