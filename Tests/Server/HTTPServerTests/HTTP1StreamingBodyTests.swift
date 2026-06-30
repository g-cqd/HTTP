//
//  HTTP1StreamingBodyTests.swift
//  HTTPServerTests
//
//  Streaming request bodies on HTTP/1.1 (Phase 1.4): a route opted in with `streamingBody()` receives
//  its body as an incremental ``RequestBody/stream(_:)`` (content-length or chunked), and the server
//  reads the whole body off the wire regardless of whether the handler drains it — so a handler that
//  abandons the body does not desync a pipelined follow-up request. The per-route body limit still
//  pre-rejects an over-limit Content-Length with `413`. Driven through the real `serve` pipeline.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Streaming request body — HTTP/1.1 (Phase 1.4)")
struct HTTP1StreamingBodyTests {
    private func serve(_ request: String, responder: any HTTPResponder) async -> String {
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)
        return String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
    }

    @Test("a streaming route receives its content-length body and can collect it")
    func collectsContentLength() async {
        let router = Router {
            Route.post("/upload") { _, body, _ in .text("got \(await body.collect().count)") }
                .streamingBody()
        }
        let wire = await serve(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello", responder: router
        )
        #expect(wire.contains(" 200 "))
        #expect(wire.hasSuffix("got 5"))
    }

    @Test("a streaming route can consume the body chunk by chunk via asStream")
    func consumesIncrementally() async {
        let router = Router {
            Route.post("/upload") { _, body, _ in
                var total = 0
                for await chunk in body.asStream {
                    total += chunk.count
                }
                return .text("total \(total)")
            }
            .streamingBody()
        }
        let wire = await serve(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world",
            responder: router
        )
        #expect(wire.hasSuffix("total 11"))
    }

    @Test("a streaming route receives a chunked body (RFC 9112 §7.1)")
    func collectsChunked() async {
        let router = Router {
            Route.post("/upload") { _, body, _ in .text("got \(await body.collect().count)") }
                .streamingBody()
        }
        let request =
            "POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        let wire = await serve(request, responder: router)
        #expect(wire.hasSuffix("got 11"))
    }

    @Test("a streaming handler that abandons the body does not desync a pipelined request")
    func abandonedStreamKeepsPipelineAligned() async {
        let router = Router {
            Route.post("/a") { _, _, _ in .text("ALPHA") }.streamingBody()  // ignores the body
            Route.get("/b") { _, _, _ in .text("BRAVO") }
        }
        // /a streams but ignores its body; the server must still consume the 5 octets so /b parses.
        let request =
            "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
            + "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        let wire = await serve(request, responder: router)
        #expect(wire.contains("ALPHA"))
        #expect(wire.contains("BRAVO"))
    }

    @Test("a streaming route still pre-rejects an over-limit Content-Length with 413")
    func streamingRespectsBodyLimit() async {
        let router = Router {
            Route.post("/upload") { _, _, _ in .text("ok") }
                .streamingBody()
                .bodyLimited(to: 4)
        }
        let wire = await serve(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789",
            responder: router
        )
        #expect(wire.contains(" 413 "))
    }
}
