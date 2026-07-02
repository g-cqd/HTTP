//
//  BodyLimitRouteTests.swift
//  HTTPServerTests
//
//  Per-route request-body limit on HTTP/1.1 (Phase 1.2, RFC 9110 §15.5.14): a route declared with
//  `bodyLimited(to:)` rejects an over-limit `Content-Length` with `413` *before* the body is buffered
//  (the handler never runs), and caps a chunked body incrementally. The route cap REPLACES the global
//  ``HTTPLimits/maxBodySize`` — it may raise it as well as tighten it (the S2 ordering fix: the size
//  policy runs after route resolution, not at parse time). A route with no limit, or a responder that
//  is not a router, falls back to the global bound. Driven through the real `serve` pipeline over a
//  `FakeConnection`.
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

    private func serve(
        _ request: String, responder: any HTTPResponder, limits: HTTPLimits = .default
    ) async -> String {
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = HTTPServer(transport: FakeTransport(), responder: responder, limits: limits)
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

    @Test("a route limit ABOVE the global admits a Content-Length the global would reject (raise)")
    func contentLengthRaisedAboveGlobal() async {
        let router = Router {
            Route.post("/upload") { _, body, _ in
                .text("got \(await body.collect().count)")
            }
            .bodyLimited(to: 64)
        }
        let body = String(repeating: "x", count: 20)
        let request = "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\n\(body)"
        // Global cap 8 < body 20 < route cap 64: the route's raise must win (the S2 ordering fix —
        // before it, the parse-time global check fired before the resolver could raise the bound).
        let wire = await serve(request, responder: router, limits: HTTPLimits(maxBodySize: 8))
        #expect(wire.contains(" 200 "))
        #expect(wire.hasSuffix("got 20"))
    }

    @Test("a route limit ABOVE the global admits a chunked body the global would reject (raise)")
    func chunkedRaisedAboveGlobal() async {
        let router = Router {
            Route.post("/upload") { _, body, _ in
                .text("got \(await body.collect().count)")
            }
            .bodyLimited(to: 64)
        }
        // One 20-octet chunk: over the 8-octet global, under the 64-octet route cap (RFC 9112 §7.1).
        let chunk = String(repeating: "y", count: 20)
        let request =
            "POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "14\r\n\(chunk)\r\n0\r\n\r\n"
        let wire = await serve(request, responder: router, limits: HTTPLimits(maxBodySize: 8))
        #expect(wire.contains(" 200 "))
        #expect(wire.hasSuffix("got 20"))
    }

    @Test("without a route limit the global still rejects with 413 (the fallback keeps its teeth)")
    func globalFallbackStillRejects() async {
        let invocation = Invocation()
        let router = Router {
            Route.post("/upload") { _, _, _ in
                invocation.mark()
                return .text("ok")
            }
        }
        let body = String(repeating: "x", count: 20)
        let request = "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\n\(body)"
        // The parser no longer enforces the size policy at parse time; the reader must still fail
        // closed at the global bound when no route raises it (RFC 9110 §15.5.14).
        let wire = await serve(request, responder: router, limits: HTTPLimits(maxBodySize: 8))
        #expect(wire.contains(" 413 "))
        #expect(invocation.didRun == false)
    }
}
