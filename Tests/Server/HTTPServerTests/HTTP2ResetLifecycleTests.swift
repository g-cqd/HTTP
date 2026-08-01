//
//  HTTP2ResetLifecycleTests.swift
//  HTTPServerTests
//
//  The fifth review's R5-P0d: a peer RST_STREAM (RFC 9113 §6.4) must retire EVERY obligation the stream
//  carries, including the two audit finding 6 left behind.
//
//  A reset streaming *response* left its relay parked on a pull permission that would never be granted
//  again and its producer parked on an offer nobody would ever take. Worse, a chunk already in the
//  mailbox when the reset landed was still applied: `sendBodyChunk` on a stream the engine had dropped
//  throws `internalError`, which is CONNECTION-scoped (RFC 9113 §5.4.1), so the consumer's `cancelAll()`
//  took every sibling stream down. That is the same connection-kill finding 6's `isStreamOpen` guard was
//  added to prevent — on the continuation path, which that guard never saw.
//
//  A reset BUFFERED request was not cancelled at all: finding 6 deferred it as benchmark-gated, so the
//  server ran a handler to completion for a request the client had explicitly withdrawn — the
//  amplification Rapid Reset exploits (CVE-2023-44487).
//

import HTTP2
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

// `.serialized` for the same reason as the other server-side HTTP/2 suites: a polling peer against a
// full serve loop starves its siblings when several run at once.
@Suite("Audit R5-P0d — HTTP/2 reset retires the response side too", .serialized)
struct HTTP2ResetLifecycleTests {
    /// The two send-window regimes a reset can land in.
    ///
    /// `1` parks the producer on its second chunk, so the relay is waiting on a permit that will never
    /// be granted again; `65_535` (the RFC 9113 §6.9.2 default) leaves it actively pumping, so a
    /// `.streamChunk` is in the mailbox behind the reset.
    private static let windows: [UInt32] = [1, 65_535]

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

    /// Whether the server queued a GOAWAY — the wire-visible signature of a connection-level fault.
    private static func hasGoAway(in bytes: [UInt8]) -> Bool {
        H2ServerWire.frames(bytes).contains { $0.type == 0x07 }
    }

    @Test(
        "a body chunk queued before a reset is dropped without faulting the connection",
        .timeLimit(.minutes(1)),
        arguments: [true, false])
    func lateChunkIsDroppedWithoutTouchingTheConnection(retiredByDriver: Bool) async throws {
        // The relay reports from its own task, so a `.streamChunk` can already be sitting in the mailbox
        // when the reset that drops the stream is applied. Two shapes, both real: the driver has torn
        // the stream down as well (`retiredByDriver`), and the engine has dropped it while the relay
        // entry is still there — the window between the engine's frame processing and the driver's.
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: ClosureResponder { _, _, _ in .text("unused") },
            limits: Self.limits
        )
        var state = HTTP2ConnectionState(
            engine: try H2Gate.handshaked(limits: Self.limits, streaming: false),
            plans: HTTP2DispatchPlans()
        )
        let streamID = HTTP2StreamID(1)
        let (wakeups, continuation) = AsyncStream.makeStream(
            of: HTTP2Wakeup.self, bufferingPolicy: .unbounded
        )
        let connection = ControllableConnection(alpn: "h2")

        let fatal = await withDiscardingTaskGroup(returning: Bool.self) { group in
            _ = try? state.engine.receive(
                H2ServerWire.headers(
                    streamID: 1, method: "GET", path: "/stream", endStream: true
                )
            )
            // A native-streaming response: HEADERS now, a relay pumping DATA behind a permit.
            _ = Self.beginStreamingResponse(
                on: server,
                streamID: streamID,
                state: &state,
                group: &group,
                into: continuation
            )
            // The peer withdraws the stream; the engine drops its record.
            _ = try? state.engine.receive(H2ServerWire.rstStream(streamID: 1, code: 0x08))
            if retiredByDriver {
                await server.resetHTTP2Stream(streamID, state: &state)
            }
            _ = state.engine.outboundBytes()  // discard everything queued up to here
            // The late chunk. Before the fix this reached `engine.sendBodyChunk`, which throws
            // `internalError` — CONNECTION-scoped — so the consumer returned "close" and `cancelAll()`
            // killed every sibling stream on the connection.
            let close = await server.applyHTTP2Wakeup(
                .streamChunk(streamID, .chunk([0x61, 0x62, 0x63])),
                state: &state,
                group: &group,
                connection: connection,
                intake: Self.makeIntake(),
                sendDeadline: IdleDeadline<ContinuousClock.Instant>(),
                into: continuation
            )
            group.cancelAll()
            return close
        }
        continuation.finish()
        for await _ in wakeups {
            // Drain whatever the relay yielded; nothing is under assertion here.
        }

        #expect(!fatal, "a late chunk for a reset stream must not close the connection")
        #expect(!Self.hasGoAway(in: state.engine.outboundBytes()))
        #expect(state.relays[streamID] == nil)
    }

    @Test(
        "a reset mid-streaming-response unwinds the producer and spares its siblings",
        .timeLimit(.minutes(1)),
        arguments: windows)
    func resetUnwindsTheProducerAndSparesSiblings(window: UInt32) async throws {
        let writes = AsyncEventProbe<Int>()
        let unwound = AsyncEventProbe<Bool>()
        let router = Router {
            Route.get("/stream") { _, _, _ in
                .streaming(contentType: "application/octet-stream") { writer in
                    defer { unwound.record(true) }
                    for index in 0 ..< 64 {
                        try await writer.write([UInt8](repeating: 0x5A, count: 4_096))
                        writes.record(index)
                    }
                }
            }
            Route.get("/fast") { _, _, _ in .text("FAST") }
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router, limits: Self.limits)
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + Self.settings(window: window)
                + H2ServerWire.headers(
                    streamID: 1, method: "GET", path: "/stream", endStream: true
                )
        )
        // 64 × 4 KiB is well past either window, so the producer is provably still mid-body: it has
        // written at least once and cannot have written all 64 chunks.
        _ = try await writes.wait(forAtLeast: 1)
        await Self.settle(rounds: 20)

        // Withdraw stream 1 and ask for stream 3 in the SAME inbound chunk: the engine processes a
        // chunk's frames in order, so stream 3 answering is proof the reset was applied first. The
        // window grants are what let the sibling's four octets actually reach the wire — stream 1's
        // body exhausted the shared connection window on the way to being withdrawn (RFC 9113 §6.9.1),
        // and under `window == 1` the sibling's own stream window starts at one octet.
        await connection.feed(
            H2ServerWire.rstStream(streamID: 1, code: 0x08)
                + H2ServerWire.headers(
                    streamID: 3, method: "GET", path: "/fast", endStream: true
                )
                + H2ServerWire.windowUpdate(streamID: 0, increment: 1 << 20)
                + H2ServerWire.windowUpdate(streamID: 3, increment: 1 << 20)
        )

        // The producer task unwinds rather than staying parked on an offer nobody will take.
        #expect(try await unwound.wait(forAtLeast: 1) == [true])

        // The sibling assertion — the one that matters. A connection-level fault took it down with the
        // reset stream, which is precisely what a peer resetting one request must never be able to do.
        while !H2ServerWire.isFinished(onStream: 3, in: await connection.sentBytes()),
            !Task.isCancelled
        {
            await Self.settle()
        }
        let body = H2ServerWire.body(onStream: 3, in: await connection.sentBytes())
        #expect(String(decoding: body, as: Unicode.UTF8.self) == "FAST")
        #expect(!Self.hasGoAway(in: await connection.sentBytes()))

        await connection.finishInbound()
        await serving.value
    }

    @Test("a reset cancels a BUFFERED request's handler", .timeLimit(.minutes(1)))
    func resetCancelsABufferedHandler() async throws {
        // Finding 6 applied the canceller to streaming routes and tunnels only. A buffered handler has
        // no body stream to abandon, so nothing whatsoever stopped it: the server ran it to completion
        // for a request the client had explicitly withdrawn.
        let parked = AsyncGate()
        let cancelled = AsyncEventProbe<Bool>()
        let router = Router {
            Route.get("/park") { _, _, _ in
                try? await parked.waitUntilOpen()
                cancelled.record(Task.isCancelled)
                return .text("parked")
            }
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router, limits: Self.limits)
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.headers(
                    streamID: 1, method: "GET", path: "/park", endStream: true
                )
        )
        try await parked.waitForWaiters(atLeast: 1)
        await connection.feed(H2ServerWire.rstStream(streamID: 1, code: 0x08))

        #expect(try await cancelled.wait(forAtLeast: 1) == [true])

        parked.open()
        await connection.finishInbound()
        await serving.value
    }

    // MARK: Scaffolding

    /// A client SETTINGS frame advertising `window` as SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113 §6.5.2).
    private static func settings(window: UInt32) -> [UInt8] {
        H2ServerWire.frame(
            type: 0x04,
            flags: 0,
            streamID: 0,
            payload: [
                0x00, 0x04,
                UInt8(window >> 24 & 0xFF), UInt8(window >> 16 & 0xFF),
                UInt8(window >> 8 & 0xFF), UInt8(window & 0xFF)
            ]
        )
    }

    /// An intake channel the direct-wakeup test never actually feeds.
    private static func makeIntake() -> BoundedByteChannel {
        BoundedByteChannel(
            highWatermark: 1_024, lowWatermark: 512, maxQueuedChunks: 4, coalescingBelow: 0
        )
    }

    /// Begins a native-streaming response on `streamID`, filing its relay in `state`.
    private static func beginStreamingResponse(
        on server: HTTPServer<ContinuousClock>,
        streamID: HTTP2StreamID,
        state: inout HTTP2ConnectionState,
        group: inout DiscardingTaskGroup,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) -> Bool {
        server.beginHTTP2Response(
            streamID: streamID,
            response: .streaming(contentType: "application/octet-stream") { writer in
                try await writer.write([UInt8](repeating: 0x5A, count: 8))
            },
            engine: &state.engine,
            group: &group,
            relays: &state.relays,
            into: continuation
        )
    }
}
