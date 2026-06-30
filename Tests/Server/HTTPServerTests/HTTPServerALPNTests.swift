//
//  HTTPServerALPNTests.swift
//  HTTPServerTests
//
//  ALPACA hardening (RFC 7301 §3.2): over TLS the server advertised its ALPN protocols, so a
//  connection must have negotiated one it serves ("h2" or "http/1.1"). A TLS connection that
//  negotiated nothing — or anything else — is refused (closed), not silently downgraded to HTTP/1.1.
//  Cleartext connections are unaffected (routed by prior knowledge / h2c-preface sniffing).
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — TLS ALPN enforcement (RFC 7301, ALPACA)")
struct HTTPServerALPNTests {
    private let ok = ClosureResponder { _, _, _ in
        ServerResponse(HTTPResponse(status: .ok), body: Array("ok".utf8))
    }

    private func wire(of connection: FakeConnection) async -> String {
        let server = HTTPServer(transport: FakeTransport(), responder: ok)
        await server.serve(connection)
        return String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
    }

    @Test("a TLS connection that negotiated http/1.1 is served as HTTP/1.1")
    func secureHTTP1Served() async {
        let connection = FakeConnection(
            id: TransportConnectionID(1),
            negotiatedApplicationProtocol: "http/1.1",
            isSecure: true,
            inbound: Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        #expect(await wire(of: connection).hasPrefix("HTTP/1.1 200 OK\r\n"))
    }

    @Test("a TLS connection that negotiated no ALPN is refused, not downgraded to HTTP/1.1")
    func secureNoALPNRefused() async {
        let connection = FakeConnection(
            id: TransportConnectionID(2),
            negotiatedApplicationProtocol: nil,
            isSecure: true,
            inbound: Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        #expect(await wire(of: connection).isEmpty)  // closed with no response
    }

    @Test("a TLS connection that negotiated an unserved protocol is refused")
    func secureUnservedProtocolRefused() async {
        let connection = FakeConnection(
            id: TransportConnectionID(3),
            negotiatedApplicationProtocol: "imap",
            isSecure: true,
            inbound: Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        #expect(await wire(of: connection).isEmpty)
    }

    @Test("a cleartext connection with no ALPN is still served (h1 by prior knowledge)")
    func cleartextStillServed() async {
        let connection = FakeConnection(
            id: TransportConnectionID(4),
            negotiatedApplicationProtocol: nil,
            isSecure: false,
            inbound: Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        #expect(await wire(of: connection).hasPrefix("HTTP/1.1 200 OK\r\n"))
    }
}
