//
//  HTTP2StreamResetTests.swift
//  HTTPServerTests
//
//  The 2026-07-31 audit's regression for finding 6: RST_STREAM is a first-class transition (RFC 9113
//  §6.4).
//
//  `handleHTTP2Event` used to end in `default:`, which silently routed `.streamReset` into the tunnel
//  handler — and that only consults `state.webSockets`. For a streaming-route request the body channel
//  was therefore neither ended nor removed: the handler parked until the whole connection died, its
//  receive credit was never returned, and the dispatch accounting never came back down. The fix is
//  making the switch exhaustive, so a future event is a compile error rather than a misroute.
//
//  It also exposes a latent connection-kill. A reset on an in-flight BUFFERED request still produced a
//  `.requestReady`, and applying a response to a stream the engine had dropped throws `internalError`
//  — a *connection*-level fault, so the wakeup handler ran `cancelAll()` and every sibling stream died
//  with it. A peer resetting one request could take down every other request on the connection.
//

import HTTP2
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Synchronization
import Testing
import WebSocket

@testable import HTTPServer

// `.serialized` for the same reason as the other server-side HTTP/2 suites: a polling peer against a
// full serve loop starves its siblings when several run at once.
@Suite("Audit F6 — HTTP/2 RST_STREAM handling", .serialized)
struct HTTP2StreamResetTests {
    /// CANCEL, INTERNAL_ERROR and ENHANCE_YOUR_CALM — codes a peer plausibly cancels with (RFC 9113 §7).
    ///
    /// The server's behavior must not vary by code: a reset is a reset.
    private static let codes: [UInt32] = [0x08, 0x02, 0x0B]

    private static var limits: HTTPLimits {
        HTTPLimits(
            streamReceiveWindow: H2ServerWire.maxFrame,
            connectionReceiveWindow: 1 << 20
        )
    }

    private static func settle(rounds: Int = 1) async {
        for _ in 0 ..< rounds {
            try? await Task.sleep(for: .milliseconds(1))
        }
    }

    @Test(
        "RST_STREAM mid-body ends the handler's body stream as a truncation, not a hang",
        .timeLimit(.minutes(1)),
        arguments: codes)
    func resetTruncatesTheBodyStream(code: UInt32) async throws {
        let observed = AsyncEventProbe<Int>()
        let router = Router {
            Route.post("/upload") { _, body, _ in
                var total = 0
                // Before the fix this loop never returned: nothing ended the channel, so the handler
                // parked here until the whole connection was torn down.
                for await chunk in body.asStream { total += chunk.count }
                observed.record(total)
                return .text("truncated=\(total)")
            }
            .streamingBody()
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router, limits: Self.limits)
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.headers(streamID: 1, path: "/upload")
                + H2ServerWire.dataFrames(streamID: 1, total: 1_024)
        )
        await Self.settle(rounds: 20)
        await connection.feed(H2ServerWire.rstStream(streamID: 1, code: code))

        // The handler observes the body ENDING early — truncation — rather than hanging. It saw at most
        // what the peer actually sent, and possibly nothing if the reset overtook the first chunk.
        let total = try await observed.wait(forAtLeast: 1)
        #expect(total.count == 1)
        #expect((total.first ?? -1) <= 1_024)

        await connection.finishInbound()
        await serving.value
    }

    @Test(
        "a sibling stream completes normally across a reset",
        .timeLimit(.minutes(1)),
        arguments: codes)
    func siblingSurvivesAReset(code: UInt32) async throws {
        // This is the latent connection-kill. Before the `isStreamOpen` guard, the reset stream's
        // handler still reported a response, `engine.respond` threw a CONNECTION-level `internalError`,
        // and the serve loop's `cancelAll()` killed the sibling too.
        let slow = AsyncGate()
        let router = Router {
            Route.get("/slow") { _, _, _ in
                try? await slow.waitUntilOpen()
                return .text("slow")
            }
            Route.get("/fast") { _, _, _ in .text("FAST") }
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router, limits: Self.limits)
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.headers(streamID: 1, method: "GET", path: "/slow", endStream: true)
        )
        try await slow.waitForWaiters(atLeast: 1)
        // The peer withdraws stream 1 while its handler is still running, and asks for stream 3 in the
        // SAME inbound chunk. The engine processes a chunk's frames in order, so stream 3's response
        // appearing is proof the reset was applied first — no sleeping, no ordering guess.
        await connection.feed(
            H2ServerWire.rstStream(streamID: 1, code: code)
                + H2ServerWire.headers(streamID: 3, method: "GET", path: "/fast", endStream: true)
        )
        while !H2ServerWire.isFinished(onStream: 3, in: await connection.sentBytes()),
            !Task.isCancelled
        {
            await Self.settle()
        }
        let body = H2ServerWire.body(onStream: 3, in: await connection.sentBytes())
        #expect(String(decoding: body, as: Unicode.UTF8.self) == "FAST")

        // Only now release stream 1's handler, so its response is unambiguously LATE. It must be
        // dropped rather than applied — applying it threw a connection-level `internalError` before the
        // `isStreamOpen` guard, which killed every sibling on the connection.
        slow.open()
        await Self.settle(rounds: 30)
        #expect(!H2ServerWire.hasResponse(onStream: 1, in: await connection.sentBytes()))

        // The connection is still alive and serving: the real regression.
        await connection.feed(
            H2ServerWire.headers(streamID: 5, method: "GET", path: "/fast", endStream: true)
        )
        while !H2ServerWire.isFinished(onStream: 5, in: await connection.sentBytes()),
            !Task.isCancelled
        {
            await Self.settle()
        }
        #expect(H2ServerWire.isFinished(onStream: 5, in: await connection.sentBytes()))

        await connection.finishInbound()
        await serving.value
    }

    @Test("RST_STREAM cancels the streaming handler's task", .timeLimit(.minutes(1)))
    func resetCancelsTheHandlerTask() async throws {
        // Abandoning the body channel unblocks a handler parked *reading*; it does nothing for one
        // parked anywhere else. The canceller is what covers that, and it is the difference between
        // stopping work the client withdrew and running it to completion for nobody.
        let parked = AsyncGate()
        let cancelled = AsyncEventProbe<Bool>()
        let router = Router {
            Route.post("/park") { _, _, _ in
                // Deliberately does NOT read the body: only cancellation can end this.
                try? await parked.waitUntilOpen()
                cancelled.record(Task.isCancelled)
                return .text("parked")
            }
            .streamingBody()
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router, limits: Self.limits)
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.headers(streamID: 1, path: "/park")
        )
        try await parked.waitForWaiters(atLeast: 1)
        await connection.feed(H2ServerWire.rstStream(streamID: 1, code: 0x08))

        #expect(try await cancelled.wait(forAtLeast: 1) == [true])

        parked.open()
        await connection.finishInbound()
        await serving.value
    }

    @Test("RST_STREAM on a tunnel fires onClose exactly once", .timeLimit(.minutes(1)))
    func resetClosesATunnelExactlyOnce() async throws {
        let closes = AsyncEventProbe<Int>()
        let counter = CloseCounter()
        let handler = ClosureWebSocketHandler { _ in [] }
        let counted = CountingWebSocketHandler(base: handler, counter: counter) {
            closes.record(counter.value)
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: counted) },
            limits: Self.limits
        )
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.extendedConnect(streamID: 1, path: "/chat")
        )
        await Self.settle(rounds: 20)
        await connection.feed(H2ServerWire.rstStream(streamID: 1, code: 0x08))

        // Exactly once, and driven by the reset rather than by the connection eventually dying.
        #expect(try await closes.wait(forAtLeast: 1) == [1])
        await connection.finishInbound()
        await serving.value
        #expect(counter.value == 1)
    }

    @Test("a reset returns the connection's accounting to zero", .timeLimit(.minutes(1)))
    func resetReturnsAccountingToZero() async throws {
        // Directly assertable now that the dispatch count is a set of stream ids rather than a counter,
        // and the credit ledger is exposed. Both were silently wrong on the reset path before.
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: ClosureResponder { _, _, _ in .text("unused") },
            limits: Self.limits
        )
        var state = try H2Gate.state(for: server, streaming: true)
        let streamID = HTTP2StreamID(1)
        state.consumption[streamID] = HTTP2ConsumptionSignal {
            // No mailbox in this unit test; only the ledger is under assertion.
        }
        state.tasks.register(
            Task {
                // A stand-in for a dispatched handler: only the ledger is under assertion.
            },
            for: streamID
        )
        _ = try state.engine.receive(H2Gate.openAndFill(streamID: streamID, count: 1_024))
        #expect(state.engine.outstandingReceiveCredit == 1_024)

        _ = try state.engine.receive(H2ServerWire.rstStream(streamID: 1, code: 0x08))
        // The handler's late `.requestReady`, dropped by `beginHTTP2Response`'s open-stream guard.
        state.tasks.release(streamID)
        state.retire(streamID)
        #expect(state.tasks.isEmpty)
        #expect(state.engine.outstandingReceiveCredit == 0)
        #expect(state.consumption.isEmpty)
        #expect(state.stalls.isEmpty)
    }
}
