//
//  BodyLimitRouteTests.swift
//  HTTPServerTests
//
//  Per-route request-body limit on HTTP/1.1 (Phase 1.2, RFC 9110 §15.5.14): a route declared with
//  `bodyLimited(to:)` rejects an over-limit `Content-Length` with `413` *before* the body is buffered
//  (the handler never runs), and caps a chunked body incrementally. A route with no limit, or a
//  responder that is not a router, falls back to the global ``HTTPLimits/maxBodySize``. Driven through
//  the real `serve` pipeline over a `FakeConnection`.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Synchronization
import Testing

@testable import HTTPServer

@Suite("Per-route body limit — HTTP/1.1 pre-buffer (RFC 9110 §15.5.14)")
struct BodyLimitRouteTests {
    /// A `Sendable` flag a handler raises, so a test can assert the handler did (not) run.
    private final class Invocation: Sendable {
        private let invoked = Mutex(false)

        func mark() { invoked.withLock { $0 = true } }

        var didRun: Bool { invoked.withLock(\.self) }

        deinit {
            // No teardown beyond ARC.
        }
    }

    private func serve(_ request: String, responder: any HTTPResponder) async -> String {
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)
        return String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
    }

    @Test("a Content-Length over the route limit is rejected with 413 before the handler runs")
    func contentLengthOverLimit() async {
        let invocation = Invocation()
        let router = Router {
            Route.post("/upload") { _, _, _ in
                invocation.mark()
                return .text("ok")
            }
            .bodyLimited(to: 8)
        }
        let body = String(repeating: "x", count: 20)
        let request = "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\n\(body)"
        let wire = await serve(request, responder: router)
        #expect(wire.contains(" 413 "))
        #expect(invocation.didRun == false)
    }

    @Test("a Content-Length within the route limit reaches the handler")
    func contentLengthWithinLimit() async {
        let router = Router {
            Route.post("/upload") { _, body, _ in
                .text("got \(await body.collect().count)")
            }
            .bodyLimited(to: 100)
        }
        let request = "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
        let wire = await serve(request, responder: router)
        #expect(wire.contains(" 200 "))
        #expect(wire.hasSuffix("got 5"))
    }

    @Test("a chunked body over the route limit is rejected with 413 before the handler runs")
    func chunkedOverLimit() async {
        let invocation = Invocation()
        let router = Router {
            Route.post("/upload") { _, _, _ in
                invocation.mark()
                return .text("ok")
            }
            .bodyLimited(to: 4)
        }
        // A single 5-octet chunk exceeds the route's 4-octet cap (RFC 9112 §7.1).
        let request =
            "POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        let wire = await serve(request, responder: router)
        #expect(wire.contains(" 413 "))
        #expect(invocation.didRun == false)
    }

    @Test("a route without a limit accepts a body the global limit allows")
    func noRouteLimit() async {
        let router = Router {
            Route.post("/x") { _, body, _ in .text("got \(await body.collect().count)") }
        }
        let body = String(repeating: "y", count: 20)
        let request = "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\n\(body)"
        let wire = await serve(request, responder: router)
        #expect(wire.contains(" 200 "))
        #expect(wire.hasSuffix("got 20"))
    }

    @Test("a non-router responder enforces no per-route limit (global only)")
    func bareResponderNoRouteLimit() async {
        let responder = ClosureResponder { _, body, _ in
            .text("got \(await body.collect().count)")
        }
        let body = String(repeating: "z", count: 20)
        let request = "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\n\(body)"
        let wire = await serve(request, responder: responder)
        #expect(wire.contains(" 200 "))
        #expect(wire.hasSuffix("got 20"))
    }
}
