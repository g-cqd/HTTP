//
//  HTTPServerShutdownTests.swift
//  HTTPServerTests
//
//  Graceful shutdown (RFC 9110 §7.6.1 / RFC 9113 §6.8): once shutdown() begins, an in-flight
//  connection finishes its current exchange and closes — HTTP/1 answers with Connection: close and
//  does not serve a following pipelined request.
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — graceful shutdown")
struct HTTPServerShutdownTests {
    @Test("a draining server answers HTTP/1 with Connection: close and stops after the exchange")
    func http1DrainsWithConnectionClose() async {
        // The responder echoes the path so the served request is identifiable on the wire.
        let responder = ClosureResponder { request, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array(request.path.utf8))
        }
        // Two pipelined requests: draining must answer the first and not serve the second.
        let pipelined = "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        let bytes = Array(pipelined.utf8)
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: bytes)
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.shutdown()  // begin draining before this connection is served
        await server.serve(connection)
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.lowercased().contains("connection: close"))
        #expect(wire.contains("/a"))  // first request served
        #expect(!wire.contains("/b"))  // second pipelined request not served during drain
    }

    @Test("shutdown is idempotent")
    func shutdownIsIdempotent() async {
        let responder = ClosureResponder { _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.shutdown()
        await server.shutdown()  // a second call must not trap or re-shut-down the transport
    }
}
