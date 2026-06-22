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
}
