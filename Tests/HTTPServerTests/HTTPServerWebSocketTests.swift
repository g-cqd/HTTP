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
            transport: FakeTransport(), responder: NotFound(), webSocketHandler: echo
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
            transport: FakeTransport(), responder: NotFound(), webSocketHandler: echo
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
            transport: FakeTransport(), responder: NotFound(), webSocketHandler: handler
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
            transport: FakeTransport(), responder: NotFound(), webSocketHandler: handler
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
            transport: FakeTransport(), responder: NotFound(), webSocketHandler: echo
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

    // MARK: Fixtures

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
