//
//  HandlerExecutionOrderingTests.swift
//  HTTPServerTests
//
//  HTTP/1.1 pipelined responses stay in request order once handlers are lifted off the reactor
//  (audit CR-F7). RFC 9112 §9.3 is unambiguous: a server "MUST send responses to those requests in
//  the same order that the requests were received" — there is no response id on the wire, so order
//  *is* the correlation.
//
//  The claim being tested is structural rather than statistical. `serveOne` is one sequential
//  statement inside `serveBody`'s `while` loop: the hop is scoped to the `respond` call, the
//  serialize-and-`send` that follows runs after it returns, and the next request is not even read
//  until `serveOne` returns `true`. So a slow handler delays the whole pipeline behind it instead of
//  overtaking it.
//
//  The proof is adversarial: four pipelined requests whose handler delays DESCEND (40, 30, 20, 10 ms).
//  Any design that dispatched them concurrently would emit them 4, 3, 2, 1 — the exact inverse. The
//  delays are `Task.sleep`, so they suspend rather than block, which is the shape most likely to
//  reorder if reordering were possible at all.
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Handler execution — pipelined HTTP/1.1 responses stay ordered (CR-F7, RFC 9112 §9.3)")
struct HandlerExecutionOrderingTests {
    /// Descending delays, so concurrent dispatch would invert the wire order.
    private static let delays: [(path: String, milliseconds: Int)] = [
        ("/a", 40), ("/b", 30), ("/c", 20), ("/d", 10)
    ]

    @Test(
        "four pipelined requests answer in request order",
        arguments: HandlerExecutionParityTests.policies
    )
    func pipelineStaysOrdered(policy: HandlerExecutionPolicy) async throws {
        let responder = ClosureResponder { request, _, _ in
            let delay = Self.delays.first { $0.path == request.path }?.milliseconds ?? 0
            try? await Task.sleep(for: .milliseconds(delay))
            return .text("body\(request.path)")
        }
        var wire = ""
        for (index, entry) in Self.delays.enumerated() {
            let last = index == Self.delays.count - 1
            wire += "GET \(entry.path) HTTP/1.1\r\nHost: x\r\n"
            wire += last ? "Connection: close\r\n\r\n" : "\r\n"
        }
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(wire.utf8))
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: responder,
            handlerExecution: policy
        )
        await server.serve(connection)

        let out = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(out.ranges(of: "HTTP/1.1 200 OK").count == Self.delays.count)
        // The bodies must appear in request order. Comparing offsets rather than a spliced string
        // keeps the assertion about ORDER and not about framing.
        let offsets = try Self.delays.map { entry in
            try #require(
                out.firstRange(of: "body\(entry.path)")?.lowerBound, "missing \(entry.path)"
            )
        }
        #expect(
            offsets == offsets.sorted(),
            "pipelined responses were emitted out of request order"
        )
    }
}
