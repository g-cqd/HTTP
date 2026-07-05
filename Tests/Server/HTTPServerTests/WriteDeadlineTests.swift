//
//  WriteDeadlineTests.swift
//  HTTPServerTests
//
//  FIX #1 / FIX #6 — progress-based write deadlines. The idle deadline is now armed around every
//  response send (buffered and streamed), not only around receives, so a slow-reading peer that fills
//  the socket send buffer is reaped at ~idleTimeout instead of pinning the serve task + connection slot
//  forever (an unmitigated Slowloris slow-read). Crucially it is PROGRESS-BASED: each chunk send resets
//  the deadline, so a legitimately slow-but-progressing transfer is NOT reaped.
//
//  Driven over a deterministic ``TestClock`` and a ``SlowReaderConnection`` whose `send` blocks until
//  the test drains it (or the reaper cancels the serve task and it throws `CancellationError`, exactly
//  as a real POSIX / Network.framework send does once the send buffer is full).
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("FIX #1/#6 — progress-based write deadlines (Slowloris slow-read)")
struct WriteDeadlineTests {
    /// (a) A peer that never reads: the response send blocks, and the idle watchdog must reap it at
    /// ~idleTimeout — closing the connection. WITHOUT the write-side deadline this hangs forever (the
    /// deadline was disarmed during sends), so this test would time out.
    @Test(
        "a peer that reads zero bytes has its stalled response send reaped at the idle timeout",
        .timeLimit(.minutes(1)))
    func stalledSendIsReaped() async {
        let clock = TestClock()
        let limits = HTTPLimits(idleTimeout: .milliseconds(500))
        let responder = ClosureResponder { _, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array("hello".utf8))
        }
        let connection = SlowReaderConnection(
            request: Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        let server = HTTPServer(
            transport: FakeTransport(), responder: responder, limits: limits, clock: clock
        )

        // The response send parks (the peer never drains). A time pump advances past every armed
        // deadline the server parks a watchdog on, so the write deadline lapses and the reap fires.
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await server.serve(connection) }
            group.addTask {
                while !Task.isCancelled {
                    try? await clock.waitForSleepers(atLeast: 1)
                    clock.advance(by: .milliseconds(500))
                }
            }
            await group.next()  // serve() returned — the stalled send was reaped and the connection closed
            group.cancelAll()
        }
        #expect(await connection.isClosed())
        // The peer drained nothing, so the response never actually reached the wire.
        #expect(await connection.sentBytes().isEmpty)
    }

    /// (b) A peer that drains SLOWLY but keeps making progress: each chunk send completes (the peer
    /// reads it) before its deadline, resetting the deadline. The cumulative transfer time far exceeds
    /// one idle window, yet the connection is NOT reaped — proving the deadline is progress-based, not a
    /// single wall-clock cap on the whole response.
    @Test(
        "a slow-but-progressing streamed response is NOT reaped — each chunk resets the deadline",
        .timeLimit(.minutes(1)))
    func progressingStreamIsNotReaped() async {
        let clock = TestClock()
        let idle = Duration.milliseconds(1_000)
        let limits = HTTPLimits(idleTimeout: idle)
        let chunks = [Array("alpha".utf8), Array("bravo".utf8), Array("gamma".utf8)]
        let responder = ClosureResponder { _, _, _ in
            .streaming(contentType: "text/plain") { writer in
                for chunk in chunks {
                    try await writer.write(chunk)
                }
            }
        }
        let connection = SlowReaderConnection(
            request: Array("GET /stream HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        let server = HTTPServer(
            transport: FakeTransport(), responder: responder, limits: limits, clock: clock
        )

        let serving = Task { await server.serve(connection) }
        // Progress pump: for each parked chunk send, advance the clock by HALF the idle window (never
        // reaching the armed deadline), then drain the chunk so the server re-arms for the next. Across
        // all sends (head + 3 chunks + terminator) the clock advances well past a full idle window, so
        // if the deadline were a single cap the connection would be reaped mid-stream.
        let pump = Task {
            while !Task.isCancelled {
                try? await connection.waitForSendParked()
                clock.advance(by: idle / 2)  // strictly less than idleTimeout — deadline never lapses
                await connection.drainOneSend()
            }
        }
        await serving.value  // completes only if the whole stream was delivered (not reaped)
        pump.cancel()

        // The full chunked body reached the wire and the stream terminated cleanly — no truncation.
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.contains("alpha"))
        #expect(wire.contains("bravo"))
        #expect(wire.contains("gamma"))
        #expect(wire.hasSuffix("0\r\n\r\n"))  // the last-chunk terminator (RFC 9112 §7.1)
    }
}

/// A ``TransportConnection`` that models a slow / non-reading peer: it delivers one staged request, then
/// every `send` blocks until the test drains it (``drainOneSend()``) or the serve task is cancelled — in
/// which case the parked send throws `CancellationError`, exactly as a real POSIX / Network.framework
/// send does when the socket send buffer is full and the write is reaped.
actor SlowReaderConnection: TransportConnection {
    nonisolated let id: TransportConnectionID
    nonisolated let peer = TransportAddress(host: "slow-reader", port: 0)
    nonisolated let negotiatedApplicationProtocol: String? = nil  // cleartext HTTP/1.1 (sniffed)
    nonisolated let isSecure = false

    private var inbound: [UInt8]
    private var deliveredRequest = false
    private var sent: [UInt8] = []
    private var closed = false
    /// Each `send` parks here until the test grants one permit; one waiter at a time (the serve loop
    /// sends sequentially). Cancellation-aware, so a reaped send unblocks with `CancellationError`.
    private let sendGate = AsyncGate()

    init(request: [UInt8], id: TransportConnectionID = TransportConnectionID(1)) {
        self.id = id
        self.inbound = request
    }

    // MARK: TransportConnection

    func receive(maxLength: Int) async throws -> [UInt8]? {
        // The peer sends exactly one request, then only reads: deliver it once, then EOF.
        guard !deliveredRequest else {
            return nil
        }
        deliveredRequest = true
        let count = min(maxLength, inbound.count)
        defer { inbound.removeFirst(count) }
        return Array(inbound.prefix(count))
    }

    func send(_ bytes: [UInt8]) async throws {
        // Block until the peer drains this write, or the reap cancels this task (throws).
        try await sendGate.waitUntilOpen()
        sent.append(contentsOf: bytes)
    }

    func close() async {
        closed = true
    }

    // MARK: Test controls

    func isClosed() -> Bool { closed }
    func sentBytes() -> [UInt8] { sent }

    /// Suspends until a `send` is parked (its write deadline is armed at that point).
    func waitForSendParked() async throws {
        try await sendGate.waitForWaiters(atLeast: 1)
    }

    /// Lets the currently-parked `send` complete — the peer drained one chunk.
    func drainOneSend() {
        sendGate.open()
    }
}
