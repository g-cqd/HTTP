//
//  StreamingResponseTests.swift
//  HTTPServerTests
//
//  Response-body streaming over HTTP/1.1 (RFC 9112 §7.1), driven through the in-memory FakeConnection:
//  a streamed body is sent with chunked transfer-coding (or Content-Length when the producer declares
//  one), a HEAD request to a streamed route sends the header section only, and the buffering fallback
//  (for engines without native streaming) collects a finite stream and rejects one past the cap.
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — response streaming (HTTP/1.1)")
struct StreamingResponseTests {
    private func serve(request: String, responder: any HTTPResponder) async -> String {
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)
        return String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
    }

    @Test("a streamed response is sent with chunked transfer-coding (RFC 9112 §7.1)")
    func chunkedStreaming() async {
        let responder = ClosureResponder { _, _ in
            .streaming(contentType: "text/plain") { writer in
                try await writer.write(Array("hello".utf8))
                try await writer.write(Array("world".utf8))
            }
        }
        let wire = await serve(request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n", responder: responder)
        #expect(wire.contains("transfer-encoding: chunked\r\n"))
        #expect(wire.contains("5\r\nhello\r\n"))
        #expect(wire.contains("5\r\nworld\r\n"))
        #expect(wire.hasSuffix("0\r\n\r\n"))  // the terminating last-chunk
        #expect(!wire.contains("content-length:"))
    }

    @Test("a streamed response with a known length uses Content-Length and no chunk framing")
    func contentLengthStreaming() async {
        let responder = ClosureResponder { _, _ in
            let stream = ResponseStream(contentLength: 10) { writer in
                try await writer.write(Array("0123456789".utf8))
            }
            return ServerResponse(HTTPResponse(status: .ok), stream: stream)
        }
        let wire = await serve(request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n", responder: responder)
        #expect(wire.contains("content-length: 10\r\n"))
        #expect(!wire.contains("transfer-encoding"))
        #expect(wire.hasSuffix("\r\n\r\n0123456789"))
    }

    @Test("a HEAD request to a streamed route sends the header section only (RFC 9112 §6.3)")
    func headStreamedOmitsBody() async {
        let responder = ClosureResponder { _, _ in
            .streaming(contentType: "text/plain") { writer in
                try await writer.write(Array("must not be sent".utf8))
            }
        }
        let wire = await serve(request: "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n", responder: responder)
        #expect(wire.contains("transfer-encoding: chunked\r\n"))
        #expect(wire.hasSuffix("\r\n\r\n"))  // header terminator, then no body
        #expect(!wire.contains("must not be sent"))
    }

    @Test("serverSentEvents streams text/event-stream chunked")
    func serverSentEvents() async {
        let responder = ClosureResponder { _, _ in
            .serverSentEvents { writer in
                try await writer.write(Array("data: tick\n\n".utf8))
            }
        }
        let wire = await serve(
            request: "GET /events HTTP/1.1\r\nHost: x\r\n\r\n", responder: responder
        )
        #expect(wire.contains("content-type: text/event-stream\r\n"))
        #expect(wire.contains("transfer-encoding: chunked\r\n"))
        #expect(wire.contains("data: tick\n\n"))
    }

    @Test("the buffering fallback collects a finite stream and rejects one past the cap")
    func collectFiniteAndCap() async {
        let stream = ResponseStream { writer in
            try await writer.write(Array("abc".utf8))
            try await writer.write(Array("def".utf8))
        }
        #expect(await stream.collect(maxBytes: 100) == Array("abcdef".utf8))
        #expect(await stream.collect(maxBytes: 4) == nil)  // 6 octets exceed the 4-octet cap
    }
}
