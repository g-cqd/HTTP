//
//  HandlerExecutionReactorAffinityTests.swift
//  HTTPServerTests
//
//  The other half of audit CR-F7: only the HANDLER subtree may leave the reactor. Readiness, parsing,
//  protocol state and socket I/O keep the single owner every engine depends on.
//
//  The HTTP/2 case is the sharp one. Its serve loop runs a reader task that owns
//  `connection.receive` for the connection's life, a send-side idle watchdog, and one sequential
//  consumer that is the sole caller of `connection.send` — HPACK state, flow-control windows and
//  frame ordering all depend on those three staying where the top-level
//  `withTaskExecutorPreference(connection.preferredTaskExecutor)` put them. A hop scoped to the
//  `respond` seams must leave every one of them untouched, under every policy.
//
//  ``ReactorPinnedConnection`` records, at each `receive`/`send`, whether the caller was still on the
//  connection's own serial executor. Since the reader is the only caller of `receive` and the
//  consumer the only caller of `send`, "no transport call ran off the reactor" is exactly the
//  invariant, observed from the transport rather than from instrumentation in the server.
//
//  These tests apply the preference themselves because `HTTPServer.accept(_:)` is private and its
//  entire body is that wrap — `withTaskExecutorPreference(connection.preferredTaskExecutor) { await
//  serve(connection) }`. Restating it here is what puts the serve hierarchy in the same topology
//  production puts it in; calling `serve` bare would test nothing, since there would be no reactor to
//  leave.
//
//  Standards: RFC 9113 §4.3 (HPACK is connection-scoped and order-dependent), §6.9 (flow control).
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Handler execution — transport I/O never leaves the reactor (CR-F7)")
struct HandlerExecutionReactorAffinityTests {
    @Test(
        "the HTTP/2 reader and send watchdog stay on the connection's executor",
        arguments: HandlerExecutionParityTests.policies
    )
    func http2TransportStaysOnTheReactor(policy: HandlerExecutionPolicy) async throws {
        let connection = ReactorPinnedConnection(
            inbound: DispatchPlanWire.http2Head(path: "/upload/abc")
                + DispatchPlanWire.http2Body(count: 16)
        )
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Self.echoRouter,
            handlerExecution: policy
        )
        await Self.servePinned(connection, by: server)

        let response = try DispatchPlanWire.decodeHTTP2(connection.sentBytes)
        #expect(response.status == "200")
        // Not vacuous: the connection was genuinely read from and written to.
        #expect(connection.transportCallCount > 0)
        #expect(connection.receivesOffReactor == 0, "the HTTP/2 reader left its event loop")
        #expect(connection.sendsOffReactor == 0, "an HTTP/2 send left its event loop")
    }

    @Test(
        "the HTTP/1.1 read and write path stays on the connection's executor",
        arguments: HandlerExecutionParityTests.policies
    )
    func http1TransportStaysOnTheReactor(policy: HandlerExecutionPolicy) async {
        let request = """
            POST /upload/abc HTTP/1.1\r
            Host: x\r
            Content-Length: 16\r
            Connection: close\r
            \r
            \(String(repeating: "x", count: 16))
            """
        let connection = ReactorPinnedConnection(inbound: Array(request.utf8))
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Self.echoRouter,
            handlerExecution: policy
        )
        await Self.servePinned(connection, by: server)

        let wire = String(decoding: connection.sentBytes, as: Unicode.UTF8.self)
        #expect(wire.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(connection.transportCallCount > 0)
        #expect(connection.receivesOffReactor == 0, "an HTTP/1.1 receive left its event loop")
        #expect(connection.sendsOffReactor == 0, "an HTTP/1.1 send left its event loop")
    }

    /// Serves `connection` under its own preferred executor — the body of `HTTPServer.accept(_:)`.
    private static func servePinned(
        _ connection: ReactorPinnedConnection,
        by server: HTTPServer<ContinuousClock>
    ) async {
        await withTaskExecutorPreference(connection.preferredTaskExecutor) {
            await server.serve(connection)
        }
    }

    /// A handler that yields, so a policy that hops has a suspension point to hop across.
    private static let echoRouter = Router {
        Route.post("/upload/:tag") { _, body, context in
            await Task.yield()
            let tag = context.parameters["tag"] ?? "?"
            return .text("tag=\(tag) bytes=\(await body.collect().count)")
        }
    }
}
