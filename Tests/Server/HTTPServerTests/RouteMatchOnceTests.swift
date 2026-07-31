//
//  RouteMatchOnceTests.swift
//  HTTPServerTests
//
//  Audit CR-F19 — one request, one walk of the routing table.
//
//  Serving a request asked the table the same question two to four times: once at the head for the body
//  limit, again at the head for the streaming opt-in, a third time to decide how to wrap the body, and
//  a fourth inside `Router.respond` to find the route it was about to run. `RoutingBenchmarks` measured
//  the fixed cost of one walk at ~1.4 µs / 3 mallocs, flat in table size — so the repetition, not the
//  linear scan, was the larger term for realistic tables.
//
//  `CountingRouter` counts a walk for each head-time `match` and for each dispatch that could not adopt
//  the head's plan, asking `Router.adopted` — the very predicate the dispatch path uses — rather than
//  restating it. Every protocol and both body modes must come to exactly one.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Route matching — exactly one table walk per request (CR-F19)")
struct RouteMatchOnceTests {
    private static let bodySize = 16

    /// A `/upload` router that echoes the captured `:tag`, optionally consuming its body as a stream.
    private static func router(streaming: Bool) -> CountingRouter {
        CountingRouter {
            let route =
                Route.post("/upload/:tag") { _, body, context in
                    let tag = context.parameters.tag ?? "?"
                    return .text("tag=\(tag) bytes=\(await body.collect().count)")
                }
                .bodyLimited(to: 4_096)
            if streaming {
                route.streamingBody()
            }
            else {
                route
            }
        }
    }

    @Test("HTTP/1.1 buffered: one walk", arguments: [false, true])
    func http1WalksOnce(streaming: Bool) async {
        let router = Self.router(streaming: streaming)
        let body = String(repeating: "x", count: Self.bodySize)
        let request = """
            POST /upload/abc HTTP/1.1\r
            Host: x\r
            Content-Length: \(Self.bodySize)\r
            Connection: close\r
            \r
            \(body)
            """
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = HTTPServer(transport: FakeTransport(), responder: router)
        await server.serve(connection)

        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasSuffix("tag=abc bytes=\(Self.bodySize)"))
        #expect(router.walkCount == 1)
    }

    @Test("HTTP/2: one walk", arguments: [false, true])
    func http2WalksOnce(streaming: Bool) async throws {
        let router = Self.router(streaming: streaming)
        let connection = FakeConnection(
            id: TransportConnectionID(1),
            inbound: DispatchPlanWire.http2Head(path: "/upload/abc")
                + DispatchPlanWire.http2Body(count: Self.bodySize)
        )
        let server = HTTPServer(transport: FakeTransport(), responder: router)
        await server.serve(connection)

        let response = try DispatchPlanWire.decodeHTTP2(await connection.sentBytes())
        #expect(response.status == "200")
        #expect(
            String(decoding: response.body, as: Unicode.UTF8.self)
                == "tag=abc bytes=\(Self.bodySize)"
        )
        #expect(router.walkCount == 1)
    }

    @Test("HTTP/3: one walk", arguments: [false, true])
    func http3WalksOnce(streaming: Bool) async throws {
        let router = Self.router(streaming: streaming)
        let server = HTTPServer(
            transport: try TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake)),
            responder: router
        )
        let quic = FakeQUICConnection()
        let stream = FakeQUICStream(
            id: QUICStreamID(0),
            direction: .bidirectional,
            inbound: [
                (
                    DispatchPlanWire.http3Head(path: "/upload/abc", contentLength: Self.bodySize)
                        + DispatchPlanWire.http3Body(count: Self.bodySize), true
                )
            ]
        )
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }
        quic.accept(stream)
        try await DispatchPlanWire.settle { stream.sendCount > 0 }

        let (status, body) = try DispatchPlanWire.decodeHTTP3(stream.sentBytes)
        #expect(status == "200")
        #expect(String(decoding: body, as: Unicode.UTF8.self) == "tag=abc bytes=\(Self.bodySize)")
        #expect(router.walkCount == 1)
    }

    // MARK: A plan from elsewhere is a cache miss, never a mis-dispatch

    @Test("a RouteMatch minted by another router is ignored and the table is scanned instead")
    func foreignMatchFallsBackToAScan() async {
        // Two tables with the SAME shape, so a handle that named an index would land on a real route
        // in either — and pick the wrong body. Only the identity check can tell them apart.
        let first = Router {
            Route.get("/a") { _, _, _ in .text("first-a") }
            Route.get("/b") { _, _, _ in .text("first-b") }
        }
        let second = Router {
            Route.get("/b") { _, _, _ in .text("second-b") }
            Route.get("/a") { _, _, _ in .text("second-a") }
        }
        let foreign = first.match(method: .get, path: "/a")
        #expect(foreign?.handle?.index == 0)  // index 0 in `first`, but `/b` in `second`

        var context = RequestContext()
        context.route = foreign
        let request = HTTPRequest(method: .get, scheme: "http", authority: "x", path: "/a")
        let response = await second.respond(to: request, body: [], context: context)
        #expect(String(decoding: response.body, as: Unicode.UTF8.self) == "second-a")
    }

    @Test("a match for a path a middleware rewrote is ignored and the table is scanned instead")
    func rewrittenPathFallsBackToAScan() async {
        let router = Router {
            Route.get("/old") { _, _, _ in .text("old") }
            Route.get("/new") { _, _, _ in .text("new") }
        }
        var context = RequestContext()
        context.route = router.match(method: .get, path: "/old")
        // A middleware between the server and the router rewrote the target; the head's match named
        // `/old` and must not be run for a request that now says `/new`.
        let request = HTTPRequest(method: .get, scheme: "http", authority: "x", path: "/new")
        let response = await router.respond(to: request, body: [], context: context)
        #expect(String(decoding: response.body, as: Unicode.UTF8.self) == "new")
    }

    @Test("a match with no handle (a custom RouteResolver's) is ignored and the table is scanned")
    func handleFreeMatchFallsBackToAScan() async {
        let router = Router {
            Route.get("/a") { _, _, _ in .text("a") }
        }
        var context = RequestContext()
        context.route = RouteMatch(route: ResolvedRoute(bodyLimit: 1))
        let request = HTTPRequest(method: .get, scheme: "http", authority: "x", path: "/a")
        let response = await router.respond(to: request, body: [], context: context)
        #expect(String(decoding: response.body, as: Unicode.UTF8.self) == "a")
    }
}
