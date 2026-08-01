//
//  HTTP2RequestBackpressureTests.swift
//  HTTPServerTests
//
//  The 2026-07-31 audit's required regression for finding 4: HTTP/2 request streaming is
//  consumption-gated end to end.
//
//  Before this, `beginHTTP2StreamingRequest` fed an `.unbounded` `AsyncStream` and the engine
//  replenished the receive window as DATA *arrived*, so the only bound on a streaming upload was the
//  per-route body cap — per stream. With the defaults that is maxBodySize 1 GiB x maxConcurrentStreams
//  128, a 128 GiB envelope, and there was no connection-level aggregate for the streaming path at all
//  (the buffered path has `streams.totalBufferedBody`; this one had nothing).
//
//  The gate makes the flow-control windows themselves the watermarks, so what these tests assert is a
//  wire-observable identity: under consumption gating the octets the server has CREDITED back with
//  WINDOW_UPDATE are exactly the octets the application has TAKEN. Offered-minus-credited is therefore
//  the live unconsumed backlog, and it must never exceed `connectionReceiveWindow` — whatever the
//  handlers do.
//
//  The peer is modelled honestly: it offers DATA only while it believes it has window, exactly as a
//  conforming client would (RFC 9113 §6.9). A peer that ignored the window would simply be reset.
//

import HTTP2
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

// `.serialized` because each test here drives a full connection — a serve loop, a reader, and up to
// eight handler children — while its own peer polls the wire. Run concurrently they starve each other
// badly enough to trip the time limits; the tests themselves are deterministic.
@Suite("Audit F4 — HTTP/2 request-body backpressure", .serialized)
struct HTTP2RequestBackpressureTests {
    /// One maximum-size DATA frame per stream window, so the peer stalls after exactly one frame
    /// unless its handler consumes — the tightest possible expression of the gate.
    private static let streamWindow = H2ServerWire.maxFrame
    /// The connection-level companion, deliberately far above the streams' combined windows.
    ///
    /// The CONNECTION window is then never the binding constraint here, so every stall these tests
    /// observe is the per-stream gate. The connection bound itself is still asserted.
    private static let connectionWindow = 1 << 20
    /// Four windows deep: completing it requires consumption to re-open the window three times.
    private static let bodySize = 4 * H2ServerWire.maxFrame

    private static var limits: HTTPLimits {
        HTTPLimits(
            streamReceiveWindow: streamWindow,
            connectionReceiveWindow: connectionWindow,
            bodyConsumptionTimeout: .seconds(60)
        )
    }

    /// Lets the server's task tree make progress between polls.
    ///
    /// A bare `Task.yield()` loop is not enough here: this test's peer polls in a tight loop while the
    /// serve loop, eight handler children, and a reader all need turns, and a hot spinner starves them
    /// badly enough to hit the time limit. A short sleep costs nothing and makes the poll honest.
    private static func settle(rounds: Int = 1) async {
        for _ in 0 ..< rounds {
            try? await Task.sleep(for: .milliseconds(1))
        }
    }

    @Test(
        "eight concurrent uploads: unconsumed bytes never exceed the connection window",
        .timeLimit(.minutes(1)))
    func concurrentUploadsStayWithinTheConnectionWindow() async throws {
        let stuck = AsyncGate()  // stream 1's handler never reads a byte until this opens
        let slow = AsyncGate()  // stream 3's handler reads only after this opens
        let router = Router {
            Route.post("/stuck") { _, _, _ in
                try? await stuck.waitUntilOpen()
                return .text("stuck")
            }
            .streamingBody()
            Route.post("/slow") { _, body, _ in
                try? await slow.waitUntilOpen()
                return .text("slow=\(await body.collect().count)")
            }
            .streamingBody()
            Route.post("/normal") { _, body, _ in
                .text("normal=\(await body.collect().count)")
            }
            .streamingBody()
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router, limits: Self.limits)
        let serving = Task { await server.serve(connection) }

        // Streams 1 (stuck) and 3 (slow) plus six normal ones — the audit's exact shape.
        let normal: [UInt32] = [5, 7, 9, 11, 13, 15]
        let all: [UInt32] = [1, 3] + normal
        var open = H2ServerWire.preface + H2ServerWire.settings()
        open += H2ServerWire.headers(streamID: 1, path: "/stuck")
        open += H2ServerWire.headers(streamID: 3, path: "/slow")
        for streamID in normal {
            open += H2ServerWire.headers(streamID: streamID, path: "/normal")
        }
        await connection.feed(open)
        try await stuck.waitForWaiters(atLeast: 1)  // the stuck handler is provably parked

        // Offer every stream a body several windows deep, pacing per stream exactly as a conforming
        // client does: never more outstanding than the window the server has credited back
        // (RFC 9113 §6.9). That pacing IS the gate — the peer can only go as fast as the handlers read.
        var offered: [UInt32: Int] = Dictionary(uniqueKeysWithValues: all.map { ($0, 0) })
        var peakBacklog = 0
        var rounds = 0
        // Streams 1 and 3 are gated shut by design and never finish in this phase; run until the six
        // normal ones have been offered in full.
        while normal.contains(where: { (offered[$0] ?? 0) < Self.bodySize }), rounds < 20_000,
            !Task.isCancelled
        {
            rounds += 1
            let sent = await connection.sentBytes()
            peakBacklog = max(peakBacklog, Self.backlog(offered, in: sent))
            // (i) The invariant: unconsumed application bytes are hard-bounded by the CONNECTION
            // window, whatever the stream count, the route body limit, or a handler's behavior.
            #expect(Self.backlog(offered, in: sent) <= Self.connectionWindow)
            let wire = Self.nextRound(&offered, over: all, in: sent)
            if wire.isEmpty {
                // Every unfinished stream is window-blocked; let the handlers drain and re-open it.
                await Self.settle()
                continue
            }
            await connection.feed(wire)
            await Self.settle()
        }
        // The bound is not vacuous — the peer really did fill more than one stream's share.
        #expect(peakBacklog > Self.streamWindow)
        // The bug-catching assertion. The stuck handler has read nothing, so it holds its credit and the
        // peer is stalled on it: its offered total is capped at ONE window. Under arrival-replenish it
        // was capped only by the route body limit — 1 GiB by default, per stream.
        #expect(offered[1] == Self.streamWindow)

        // (ii) The six normal streams complete while the stuck one holds its window shut.
        for streamID in normal {
            while !H2ServerWire.isFinished(
                onStream: streamID, in: await connection.sentBytes()
            ), !Task.isCancelled {
                await Self.settle()
            }
        }
        #expect(!H2ServerWire.hasResponse(onStream: 1, in: await connection.sentBytes()))

        // (iii) Releasing the slow handler re-opens its window: it drains what was already queued, the
        // rest of its body flows, and the stream completes with nothing lost while it was stalled.
        slow.open()
        rounds = 0
        while (offered[3] ?? 0) < Self.bodySize, rounds < 20_000, !Task.isCancelled {
            rounds += 1
            let wire = Self.nextRound(&offered, over: [3], in: await connection.sentBytes())
            if wire.isEmpty {
                await Self.settle()
                continue
            }
            await connection.feed(wire)
            await Self.settle()
        }
        while !H2ServerWire.isFinished(onStream: 3, in: await connection.sentBytes()),
            !Task.isCancelled
        {
            await Self.settle()
        }
        let slowBody = H2ServerWire.body(onStream: 3, in: await connection.sentBytes())
        #expect(String(decoding: slowBody, as: Unicode.UTF8.self) == "slow=\(Self.bodySize)")

        // (iv) Tearing the connection down unwinds every handler, including the one still parked on a
        // body stream it will never finish reading — no continuation is left dangling, so this returns.
        stuck.open()
        await connection.finishInbound()
        await serving.value
    }

    /// Unconsumed octets the peer is holding, from the server's own connection credit.
    ///
    /// The server's first stream-0 WINDOW_UPDATE is the preface one raising the connection window from
    /// the RFC 9113 §6.9.2 floor of 65,535 to the configured size. It credits nothing consumed, so it is
    /// discounted here — counting it would make the backlog read as negative.
    private static func backlog(_ offered: [UInt32: Int], in sent: [UInt8]) -> Int {
        let preface = connectionWindow - 65_535
        let credited = max(0, H2ServerWire.creditedBytes(onStream: 0, in: sent) - preface)
        return offered.values.reduce(0, +) - credited
    }

    /// One conforming round: a frame for each stream that still has both window and body left.
    private static func nextRound(
        _ offered: inout [UInt32: Int],
        over streams: [UInt32],
        in sent: [UInt8]
    ) -> [UInt8] {
        var connectionRoom = connectionWindow - backlog(offered, in: sent)
        var wire: [UInt8] = []
        for streamID in streams {
            guard let count = offered[streamID], count < bodySize else {
                continue
            }
            let held = count - H2ServerWire.creditedBytes(onStream: streamID, in: sent)
            let room = min(streamWindow - held, connectionRoom, bodySize - count)
            guard room >= H2ServerWire.maxFrame else {
                continue
            }
            offered[streamID] = count + H2ServerWire.maxFrame
            connectionRoom -= H2ServerWire.maxFrame
            wire += H2ServerWire.dataFrames(
                streamID: streamID,
                total: H2ServerWire.maxFrame,
                endStream: count + H2ServerWire.maxFrame == bodySize
            )
        }
        return wire
    }

    /// The head-of-line consequence of gating, bounded — the DECISION, driven directly.
    ///
    /// One non-consuming handler holds part of the shared connection window and slows every sibling.
    /// That is HTTP/2's semantics, so the answer is not to prevent it but to bound it. The sweeper task
    /// only decides *when* to look; the rule itself is a pure function of byte progress, so it is
    /// exercised here with no clock at all.
    @Test("a stream holding credit with no byte progress is over budget after two sweeps")
    func sweepDecisionIsByteProgressBased() throws {
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: ClosureResponder { _, _, _ in .text("unused") },
            limits: Self.limits
        )
        var state = try H2Gate.state(for: server, streaming: true)
        let stalled = HTTP2StreamID(1)
        let live = HTTP2StreamID(3)
        for streamID in [stalled, live] {
            state.consumption[streamID] = HTTP2ConsumptionSignal {
                // The wakeup edge is irrelevant here; only the credit bookkeeping is under test.
            }
            _ = try state.engine.receive(H2Gate.openAndFill(streamID: streamID, count: 1_024))
        }
        // One sweep is not enough: a handler that merely happened to be between chunks must not be
        // punished for it.
        #expect(state.sweepStalls().isEmpty)
        // The live stream reports progress; the stalled one does not.
        state.engine.replenishReceiveWindow(live, consumed: 1_024)
        state.noteConsumption(live)
        #expect(state.sweepStalls() == [stalled])
        // A stream holding no credit is idle, not stalling — that is the connection idle timeout's job.
        state.engine.replenishReceiveWindow(stalled, consumed: 1_024)
        state.noteConsumption(stalled)
        #expect(state.sweepStalls().isEmpty)
        #expect(state.sweepStalls().isEmpty)
    }

    /// The same rule end to end: the sweeper task fires, the stalled stream is reset, siblings survive.
    @Test(
        "a swept stream is reset with ENHANCE_YOUR_CALM while its sibling continues",
        .timeLimit(.minutes(1)))
    func aNonConsumingStreamIsSwept() async throws {
        let stuck = AsyncGate()
        let router = Router {
            Route.post("/stuck") { _, _, _ in
                try? await stuck.waitUntilOpen()
                return .text("stuck")
            }
            .streamingBody()
            Route.post("/normal") { _, body, _ in
                .text("normal=\(await body.collect().count)")
            }
            .streamingBody()
        }
        // A short consumption budget so the sweeper's own timer drives this rather than a test hook;
        // the decision it applies is the deterministic one asserted above.
        let limits = HTTPLimits(
            streamReceiveWindow: Self.streamWindow,
            connectionReceiveWindow: Self.connectionWindow,
            bodyConsumptionTimeout: .milliseconds(40)
        )
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router, limits: limits)
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.headers(streamID: 1, path: "/stuck")
                + H2ServerWire.headers(streamID: 3, path: "/normal")
        )
        try await stuck.waitForWaiters(atLeast: 1)
        // Stream 1 takes a full window and consumes none of it; stream 3 takes one frame and drains.
        await connection.feed(H2ServerWire.dataFrames(streamID: 1, total: Self.streamWindow))
        await connection.feed(H2ServerWire.dataFrames(streamID: 3, total: H2ServerWire.maxFrame))
        while H2ServerWire.resetCode(onStream: 1, in: await connection.sentBytes()) == nil,
            !Task.isCancelled
        {
            await Self.settle()
        }
        // ENHANCE_YOUR_CALM = 0x0b (RFC 9113 §7): the peer is conforming, the server cannot keep up
        // with this one stream — so only this one stream dies.
        #expect(H2ServerWire.resetCode(onStream: 1, in: await connection.sentBytes()) == 0x0B)

        // The sibling is untouched: a swept stall is surgical, never connection-fatal.
        await connection.feed(
            H2ServerWire.dataFrames(streamID: 3, total: H2ServerWire.maxFrame, endStream: true)
        )
        while !H2ServerWire.isFinished(onStream: 3, in: await connection.sentBytes()),
            !Task.isCancelled
        {
            await Self.settle()
        }
        let body = H2ServerWire.body(onStream: 3, in: await connection.sentBytes())
        let expected = "normal=\(2 * H2ServerWire.maxFrame)"
        #expect(String(decoding: body, as: Unicode.UTF8.self) == expected)

        stuck.open()
        await connection.finishInbound()
        await serving.value
    }

    @Test(
        "a handler that never reads holds exactly its own window and no more",
        .timeLimit(.minutes(1)))
    func aNonConsumingHandlerHoldsOnlyItsOwnWindow() async throws {
        let stuck = AsyncGate()
        let router = Router {
            Route.post("/stuck") { _, _, _ in
                try? await stuck.waitUntilOpen()
                return .text("stuck")
            }
            .streamingBody()
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router, limits: Self.limits)
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.headers(streamID: 1, path: "/stuck")
        )
        try await stuck.waitForWaiters(atLeast: 1)

        // Offer exactly one window. Under arrival-replenish the server credited every octet straight
        // back and the peer could have kept going to the 1 GiB route cap; gated, it credits nothing.
        await connection.feed(
            H2ServerWire.dataFrames(streamID: 1, total: Self.streamWindow)
        )
        await Self.settle(rounds: 50)
        let credited = H2ServerWire.creditedBytes(onStream: 1, in: await connection.sentBytes())
        #expect(credited == 0)

        stuck.open()
        await connection.finishInbound()
        await serving.value
    }

    @Test("a draining handler's consumption is what re-opens the window", .timeLimit(.minutes(1)))
    func consumptionReopensTheWindow() async {
        let router = Router {
            Route.post("/drain") { _, body, _ in
                .text("drained=\(await body.collect().count)")
            }
            .streamingBody()
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router, limits: Self.limits)
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.headers(streamID: 1, path: "/drain")
        )
        // A body four windows deep: it can only complete if consumption keeps re-opening the window,
        // which is the positive half of the gate (the peer here is deliberately NOT window-aware, so
        // the engine would reset it on FLOW_CONTROL_ERROR if credit were not flowing).
        let body = 4 * Self.streamWindow
        var offered = 0
        while offered < body, !Task.isCancelled {
            let sent = await connection.sentBytes()
            let credited = H2ServerWire.creditedBytes(onStream: 1, in: sent)
            guard offered - credited < Self.streamWindow else {
                await Self.settle()
                continue
            }
            let chunk = min(H2ServerWire.maxFrame, body - offered)
            offered += chunk
            await connection.feed(
                H2ServerWire.dataFrames(
                    streamID: 1, total: chunk, endStream: offered == body
                )
            )
        }
        while !H2ServerWire.isFinished(onStream: 1, in: await connection.sentBytes()),
            !Task.isCancelled
        {
            await Self.settle()
        }
        let responseBody = H2ServerWire.body(onStream: 1, in: await connection.sentBytes())
        #expect(String(decoding: responseBody, as: Unicode.UTF8.self) == "drained=\(body)")

        await connection.finishInbound()
        await serving.value
    }
}
