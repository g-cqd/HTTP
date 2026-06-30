//
//  HTTPServerTests.swift
//  HTTPServerTests
//
//  RED→GREEN driver for the HTTP/1.1 server runtime, exercised over an in-memory FakeConnection so
//  the read → parse → respond → serialize → write pipeline is tested without sockets.
//

import HTTPCore
import HTTPTestSupport
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
        return String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
    }

    @Test("serves a request and writes the serialized response")
    func servesRequest() async {
        let responder = ClosureResponder { request, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array("hi from \(request.path)".utf8))
        }
        let wire = await serve(
            request: "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n", responder: responder
        )
        #expect(wire.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(wire.contains("hi from /hello"))
    }

    @Test("passes the decoded body to the responder")
    func passesBody() async {
        let responder = ClosureResponder { _, body, _ in
            ServerResponse(HTTPResponse(status: .ok), body: await body.collect())
        }
        let wire = await serve(
            request: "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
            responder: responder
        )
        #expect(wire.hasSuffix("\r\n\r\nhello"))
    }

    @Test("maps a smuggling/parse error to a 400 response")
    func mapsParseErrorToStatus() async {
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        // Content-Length AND Transfer-Encoding together — rejected (RFC 9112 §6.1).
        let wire = await serve(
            request:
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            responder: responder
        )
        #expect(wire.hasPrefix("HTTP/1.1 400 Bad Request\r\n"))
    }

    @Test("maps an unsupported Transfer-Encoding to 501 (RFC 9112 §6.1; audit H1-F5)")
    func mapsUnsupportedTransferEncodingTo501() async {
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let wire = await serve(
            request: "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
            responder: responder
        )
        #expect(wire.hasPrefix("HTTP/1.1 501 "))
    }

    @Test("keeps the connection alive and serves pipelined requests")
    func keepsConnectionAlive() async {
        let responder = ClosureResponder { request, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array(request.path.utf8))
        }
        // Two requests pipelined on one persistent connection (RFC 9112 §9.3).
        let wire = await serve(
            request: "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n",
            responder: responder
        )
        #expect(wire.ranges(of: "HTTP/1.1 200 OK").count == 2)
        #expect(wire.hasSuffix("\r\n\r\n/b"))  // second response served after the first
        #expect(!wire.contains(" 400 "))  // a clean EOF on a boundary is not an error
    }

    @Test("a 3-deep pipeline is served in order — the cursor advances per request, no shift (L3)")
    func threeDeepPipeline() async {
        let responder = ClosureResponder { request, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array(request.path.utf8))
        }
        // Three requests buffered together: the keep-alive cursor advances past each consumed request
        // in place (no per-request `removeFirst` memmove) and each later head parses from a non-zero
        // offset. All three must be served, in order (audit L3 — the ring buffer).
        let wire = await serve(
            request: "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"
                + "GET /c HTTP/1.1\r\nHost: x\r\n\r\n",
            responder: responder
        )
        #expect(wire.ranges(of: "HTTP/1.1 200 OK").count == 3)
        #expect(wire.contains("\r\n\r\n/a"))
        #expect(wire.contains("\r\n\r\n/b"))
        #expect(wire.hasSuffix("\r\n\r\n/c"))  // /c served last (order preserved)
    }

    @Test("a pipelined request with a body frames head + body from a non-zero cursor (L3)")
    func pipelinedRequestWithBody() async {
        let responder = ClosureResponder { request, body, _ in
            let bytes = await body.collect()
            return ServerResponse(
                HTTPResponse(status: .ok), body: bytes.isEmpty ? Array(request.path.utf8) : bytes
            )
        }
        // Two bodied POSTs pipelined: the second request's head AND its Content-Length body are framed
        // at a non-zero buffer offset (the cursor), exercising the `bodyStart` math (audit L3).
        let wire = await serve(
            request: "POST /one HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
                + "POST /two HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nworld",
            responder: responder
        )
        #expect(wire.ranges(of: "HTTP/1.1 200 OK").count == 2)
        #expect(wire.contains("\r\n\r\nhello"))  // first body echoed
        // second body echoed, framed from a non-zero cursor
        #expect(wire.hasSuffix("\r\n\r\nworld"))
    }

    @Test("honors Connection: close — serves one request then stops")
    func honorsConnectionClose() async {
        let responder = ClosureResponder { request, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array(request.path.utf8))
        }
        // The first request asks to close; the pipelined second must be ignored (RFC 9110 §7.6.1).
        let wire = await serve(
            request:
                "GET /a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n",
            responder: responder
        )
        #expect(wire.ranges(of: "HTTP/1.1 200 OK").count == 1)
        #expect(wire.hasSuffix("\r\n\r\n/a"))
    }

    @Test("an HTTP/1.0 request closes after one response by default (RFC 9112 §9.3)")
    func http10ClosesByDefault() async {
        let responder = ClosureResponder { request, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array(request.path.utf8))
        }
        // Two pipelined HTTP/1.0 requests; 1.0 is non-persistent by default, so only /a is served.
        let wire = await serve(
            request: "GET /a HTTP/1.0\r\n\r\nGET /b HTTP/1.0\r\n\r\n", responder: responder
        )
        #expect(wire.ranges(of: "HTTP/1.1 200 OK").count == 1)
        #expect(wire.hasSuffix("\r\n\r\n/a"))
    }

    @Test("an HTTP/1.0 request with Connection: keep-alive persists (RFC 9112 §9.3)")
    func http10KeepAlive() async {
        let responder = ClosureResponder { request, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array(request.path.utf8))
        }
        let wire = await serve(
            request: "GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"
                + "GET /b HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
            responder: responder
        )
        #expect(wire.ranges(of: "HTTP/1.1 200 OK").count == 2)
    }

    @Test("a HEAD response carries Content-Length but no body (RFC 9112 §6.3)")
    func headOmitsBody() async {
        let responder = ClosureResponder { _, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array("0123456789".utf8))
        }
        let wire = await serve(request: "HEAD /x HTTP/1.1\r\nHost: x\r\n\r\n", responder: responder)
        // The Content-Length is the length the equivalent GET would send; the body itself is omitted.
        #expect(wire.contains("content-length: 10\r\n"))
        #expect(wire.hasSuffix("\r\n\r\n"))
    }

    @Test("an error response signals connection close (RFC 9112 §9.6)")
    func errorResponseSignalsClose() async {
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let wire = await serve(
            request:
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            responder: responder
        )
        #expect(wire.hasPrefix("HTTP/1.1 400 Bad Request\r\n"))
        #expect(wire.contains("connection: close\r\n"))
    }

    @Test(
        "an idle persistent connection is closed after the keep-alive timeout (Slowloris)",
        .timeLimit(.minutes(1))
    )
    func idleTimeoutClosesConnection() async {
        let clock = TestClock()
        let limits = HTTPLimits(keepAliveTimeout: .milliseconds(100))
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let connection = HangingConnection(id: TransportConnectionID(1))
        let server = HTTPServer(
            transport: FakeTransport(), responder: responder, limits: limits, clock: clock
        )

        // Serve concurrently with a time pump that advances past every keep-alive deadline the server
        // arms (the peer never sends), until serve() closes the connection. Zero real-time waiting —
        // each `advance` fires the parked `clock.sleep` immediately, with no `Task.sleep`/`yield`.
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await server.serve(connection) }
            group.addTask {
                while !Task.isCancelled {
                    try? await clock.waitForSleepers(atLeast: 1)
                    clock.advance(by: .milliseconds(100))
                }
            }
            await group.next()  // serve() returned — the connection timed out and closed
            group.cancelAll()  // stop the pump
        }
        #expect(await connection.isClosed())
    }

    @Test(
        "rejects connections beyond maxConnectionsPerClient for one peer",
        .timeLimit(.minutes(1))
    )
    func perClientConnectionCap() async throws {
        let limits = HTTPLimits(maxConnectionsPerClient: 2)
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let peer = TransportAddress(host: "203.0.113.7", port: 0)
        let probe = AsyncEventProbe<TransportConnectionID>()
        let connections = (1 ... 3)
            .map {
                HangingConnection(
                    id: TransportConnectionID(UInt64($0)), peer: peer, admissionProbe: probe
                )
            }
        let server = HTTPServer(
            transport: FakeTransport(connections: connections), responder: responder, limits: limits
        )

        let run = Task { try? await server.run() }
        // Each connection records once its admission is decided (admitted → read, rejected → close).
        // Await all three decisions instead of guessing with a `Task.sleep`.
        _ = try await probe.wait(forAtLeast: 3)

        // The cap is 2, so exactly one of the three same-peer connections is rejected (closed).
        var closedCount = 0
        for connection in connections where await connection.isClosed() { closedCount += 1 }
        #expect(closedCount == 1)

        run.cancel()
        _ = await run.value
    }

    @Test(
        "rejects connections beyond the global maxConnections (audit T-F2)", .timeLimit(.minutes(1))
    )
    func globalConnectionCap() async throws {
        // A high per-client cap with distinct peers, so only the *global* cap can trip.
        let limits = HTTPLimits(maxConnectionsPerClient: 100, maxConnections: 2)
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let probe = AsyncEventProbe<TransportConnectionID>()
        let connections = (1 ... 3)
            .map {
                HangingConnection(
                    id: TransportConnectionID(UInt64($0)),
                    peer: TransportAddress(host: "198.51.100.\($0)", port: 0),
                    admissionProbe: probe
                )
            }
        let server = HTTPServer(
            transport: FakeTransport(connections: connections), responder: responder, limits: limits
        )

        let run = Task { try? await server.run() }
        _ = try await probe.wait(forAtLeast: 3)  // every admission decided

        var closedCount = 0
        for connection in connections where await connection.isClosed() { closedCount += 1 }
        #expect(closedCount == 1)  // global cap 2 → exactly one of three is rejected

        run.cancel()
        _ = await run.value
    }

    @Test("rejects a header section that never terminates, before exhausting memory")
    func boundsUnterminatedHeaderSection() async {
        // Small limits keep the test fast: the cap is 1 KiB + 4 KiB. The peer streams 16 KiB of
        // header bytes with no terminating CRLF CRLF — the parser's size limits cannot run without
        // a terminator, so the server must cap the buffer and fail closed with 431.
        let limits = HTTPLimits(maxRequestLineLength: 1_024, maxHeaderListSize: 4 * 1_024)
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let flood = "GET / HTTP/1.1\r\nX-Pad: " + String(repeating: "A", count: 16 * 1_024)
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(flood.utf8))
        let server = HTTPServer(transport: FakeTransport(), responder: responder, limits: limits)
        await server.serve(connection)
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasPrefix("HTTP/1.1 431"))
        #expect(wire.contains("connection: close\r\n"))
    }

    @Test("frames a Content-Length body delivered one octet per read (parse head once)")
    func incrementalContentLengthBody() async {
        let responder = ClosureResponder { _, body, _ in
            ServerResponse(HTTPResponse(status: .ok), body: await body.collect())
        }
        let request = "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
        let connection = DribblingConnection(
            id: TransportConnectionID(1), inbound: Array(request.utf8), chunkSize: 1
        )
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasSuffix("\r\n\r\nhello"))
    }

    @Test("decodes a chunked body delivered across reads (head not re-parsed)")
    func incrementalChunkedBody() async {
        let responder = ClosureResponder { _, body, _ in
            ServerResponse(HTTPResponse(status: .ok), body: await body.collect())
        }
        // Two chunks then the terminating zero-size chunk (RFC 9112 §7.1) → body "Wikipedia".
        let request =
            "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        let connection = DribblingConnection(
            id: TransportConnectionID(1), inbound: Array(request.utf8), chunkSize: 3
        )
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasSuffix("\r\n\r\nWikipedia"))
    }
}
