//
//  ResponderGenerationTests.swift
//  HTTPServerTests
//
//  Audit CR-F12 — a request is served by exactly one generation of the hot-swappable responder.
//
//  The server serves a request in phases: resolve the matched route from the head (its body limit, its
//  streaming opt-in), read the body, then dispatch to the responder. Each phase used to reread the
//  responder mutex on its own, so a `reloadResponder` landing between two of them let one request take
//  its body policy from generation N and its handler from generation N+1 — a combination *neither*
//  table describes, and the way an old permissive limit gets applied to a newly restrictive route.
//
//  These tests stage that race deterministically rather than hoping to hit it: the request's head is
//  delivered, the test waits until the router reports the head resolved (`CountingRouter`'s probe),
//  reloads, and only then delivers the body. The old generation's limit admits the body and the old
//  generation's handler must be the one that answers.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Responder generations — one request observes exactly one (CR-F12)")
struct ResponderGenerationTests {
    /// The body size: comfortably inside the old generation's limit, well past the new one's.
    private static let bodySize = 32
    private static let oldLimit = 1_024
    private static let newLimit = 8

    /// A router labelled `label`, whose `/upload` route caps bodies at `limit` and answers `label`.
    private static func generation(
        _ label: String,
        limit: Int,
        resolved: AsyncEventProbe<String>? = nil
    ) -> CountingRouter {
        CountingRouter(resolved: resolved) {
            Route.post("/upload") { _, _, _ in .text(label) }
                .bodyLimited(to: limit)
        }
    }

    @Test("HTTP/1.1: a reload between head parse and dispatch does not split the generation")
    func http1ReloadDoesNotSplitTheGeneration() async throws {
        let resolved = AsyncEventProbe<String>()
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Self.generation("A", limit: Self.oldLimit, resolved: resolved)
        )
        let connection = ControllableConnection(id: TransportConnectionID(1), alpn: nil)
        let serving = Task { await server.serve(connection) }
        defer { serving.cancel() }

        // The head alone: the reader parses it, resolves `/upload` against generation A (whose limit
        // admits the declared length), and then parks waiting for the body.
        await connection.feed(
            Array(
                """
                POST /upload HTTP/1.1\r
                Host: x\r
                Content-Length: \(Self.bodySize)\r
                Connection: close\r
                \r

                """
                .utf8
            )
        )
        _ = try await resolved.wait(forAtLeast: 1)

        // Swap the table while the reader is parked mid-request. Generation B would have rejected this
        // body outright (413), and its handler answers "B".
        server.reloadResponder(Self.generation("B", limit: Self.newLimit))

        await connection.feed(Array(repeating: UInt8(ascii: "x"), count: Self.bodySize))
        await connection.finishInbound()
        await serving.value

        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        // Generation A's limit admitted the body, so generation A's handler must have answered it.
        #expect(wire.hasSuffix("\r\n\r\nA"))
        #expect(!wire.contains(" 413 "))
    }

    @Test("a reload increments the generation counter and re-resolves the router face once")
    func reloadMintsANewGeneration() {
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Self.generation("A", limit: Self.oldLimit)
        )
        let first = server.currentSnapshot
        #expect(first.generation == 0)
        #expect(first.resolver != nil)  // the `as?` ran once, at construction

        server.reloadResponder(ClosureResponder { _, _, _ in .text("plain") })
        let second = server.currentSnapshot
        #expect(second.generation == 1)
        // A non-routing responder leaves the server on its global defaults.
        #expect(second.resolver == nil)
        #expect(second.hasWebSocketRoutes == false)
    }
}
