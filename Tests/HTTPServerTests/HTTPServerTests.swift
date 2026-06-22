//
//  HTTPServerTests.swift
//  HTTPServerTests
//
//  RED→GREEN driver for the HTTP/1.1 server runtime, exercised over an in-memory FakeConnection so
//  the read → parse → respond → serialize → write pipeline is tested without sockets.
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — request/response pipeline")
struct HTTPServerTests {

    private func serve(
        request: String,
        responder: any HTTPResponder
    ) async -> String {
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)
        return String(decoding: await connection.sentBytes(), as: UTF8.self)
    }

    @Test("serves a request and writes the serialized response")
    func servesRequest() async {
        let responder = ClosureResponder { request, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array("hi from \(request.path)".utf8))
        }
        let wire = await serve(
            request: "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n", responder: responder)
        #expect(wire.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(wire.contains("hi from /hello"))
    }

    @Test("passes the decoded body to the responder")
    func passesBody() async {
        let responder = ClosureResponder { _, body in
            ServerResponse(HTTPResponse(status: .ok), body: body)
        }
        let wire = await serve(
            request: "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
            responder: responder)
        #expect(wire.hasSuffix("\r\n\r\nhello"))
    }

    @Test("maps a smuggling/parse error to a 400 response")
    func mapsParseErrorToStatus() async {
        let responder = ClosureResponder { _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        // Content-Length AND Transfer-Encoding together — rejected (RFC 9112 §6.1).
        let wire = await serve(
            request:
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            responder: responder)
        #expect(wire.hasPrefix("HTTP/1.1 400 Bad Request\r\n"))
    }

    @Test("keeps the connection alive and serves pipelined requests")
    func keepsConnectionAlive() async {
        let responder = ClosureResponder { request, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array(request.path.utf8))
        }
        // Two requests pipelined on one persistent connection (RFC 9112 §9.3).
        let wire = await serve(
            request: "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n",
            responder: responder)
        #expect(wire.ranges(of: "HTTP/1.1 200 OK").count == 2)
        #expect(wire.hasSuffix("\r\n\r\n/b"))  // second response served after the first
        #expect(!wire.contains(" 400 "))  // a clean EOF on a boundary is not an error
    }

    @Test("honors Connection: close — serves one request then stops")
    func honorsConnectionClose() async {
        let responder = ClosureResponder { request, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array(request.path.utf8))
        }
        // The first request asks to close; the pipelined second must be ignored (RFC 9110 §7.6.1).
        let wire = await serve(
            request:
                "GET /a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n",
            responder: responder)
        #expect(wire.ranges(of: "HTTP/1.1 200 OK").count == 1)
        #expect(wire.hasSuffix("\r\n\r\n/a"))
    }

    @Test("a HEAD response carries Content-Length but no body (RFC 9112 §6.3)")
    func headOmitsBody() async {
        let responder = ClosureResponder { _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array("0123456789".utf8))
        }
        let wire = await serve(request: "HEAD /x HTTP/1.1\r\nHost: x\r\n\r\n", responder: responder)
        // The Content-Length is the length the equivalent GET would send; the body itself is omitted.
        #expect(wire.contains("content-length: 10\r\n"))
        #expect(wire.hasSuffix("\r\n\r\n"))
    }

    @Test("an error response signals connection close (RFC 9112 §9.6)")
    func errorResponseSignalsClose() async {
        let responder = ClosureResponder { _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let wire = await serve(
            request:
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            responder: responder)
        #expect(wire.hasPrefix("HTTP/1.1 400 Bad Request\r\n"))
        #expect(wire.contains("connection: close\r\n"))
    }
}
