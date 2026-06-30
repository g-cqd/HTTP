//
//  HTTPRouterTests.swift
//  HTTPServerTests
//
//  Phase 3.7 — the pluggable routing seam: a custom ``HTTPRouter`` (not the built-in ``Router``) drives
//  the server as its responder, and the built-in router conforms to the seam.
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Phase 3.7 — pluggable HTTPRouter seam")
struct HTTPRouterTests {
    /// A minimal custom router: a fixed response, resolving no per-route metadata.
    private struct FixedRouter: HTTPRouter {
        func respond(
            to _: HTTPRequest, body _: RequestBody, context _: RequestContext
        ) async -> ServerResponse {
            .text("fixed")
        }

        func resolve(method _: HTTPMethod, path _: String) -> ResolvedRoute? { nil }

        func resolveWebSocket(path _: String) -> ResolvedRoute? { nil }

        var hasWebSocketRoutes: Bool { false }
    }

    @Test("a custom HTTPRouter drives the server as its responder")
    func customRouterServes() async {
        let server = HTTPServer(transport: FakeTransport(), responder: FixedRouter())
        let connection = FakeConnection(
            id: TransportConnectionID(1),
            inbound: Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        await server.serve(connection)
        let head = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(head.hasPrefix("HTTP/1.1 200 "))
        #expect(head.contains("fixed"))
    }

    @Test("the built-in Router conforms to HTTPRouter")
    func builtInRouterConforms() {
        let router: any HTTPRouter = Router { Route.get("/") { _, _, _ in .text("hi") } }
        #expect(router.resolve(method: .get, path: "/") != nil)
        #expect(router.hasWebSocketRoutes == false)
    }
}
