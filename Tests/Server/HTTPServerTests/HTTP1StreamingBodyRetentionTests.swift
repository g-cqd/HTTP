//
//  HTTP1StreamingBodyRetentionTests.swift
//  HTTPServerTests
//
//  Audit CR-F5 / addendum P0.4 — a streamed HTTP/1.1 request body must cost bounded memory, not
//  O(body size). These drive ``HTTPServer/serveOne(_:deadline:buffer:start:responseBuffer:)`` directly
//  rather than through `serve`, because the thing under test is the connection read buffer it threads
//  `inout`: its *capacity* between exchanges is the retention number, and it is invisible from outside.
//
//  The uploads are synthesized (``SynthesizedUploadConnection``) so 256 MiB crosses the wire without
//  256 MiB existing anywhere — including in the harness, which would otherwise mask the regression.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Synchronization
import Testing

@testable import HTTPServer

@Suite("Streamed request-body retention — HTTP/1.1 (audit CR-F5)")
struct HTTP1StreamingBodyRetentionTests {
    /// A quarter-gibibyte upload: far past any buffer the server may legitimately hold.
    private static let uploadSize = 256 << 20

    /// Limits that admit ``uploadSize``, so the *size* is not what refuses the request.
    ///
    /// The default ``HTTPLimits/maxBodySize`` is 16 MiB (audit CR-F15) and a quarter-gibibyte upload is
    /// exactly the shape it now refuses with `413` — correctly, and not what this suite measures.
    /// Retention is about what the server *holds* while streaming a body it has accepted, so the body
    /// cap is raised here while every retention-relevant knob (`keepAliveBufferCapacity`,
    /// `requestBodyWindowSize`) stays at its default, which is where the assertions read it from.
    private static let streamingLimits = HTTPLimits.default.with { $0.maxBodySize = uploadSize }

    /// What a streaming handler observed, recorded across isolation domains.
    private final class ChunkLog: Sendable {
        private let state = Mutex<(count: Int, total: Int, largest: Int)>((0, 0, 0))

        func record(_ chunk: [UInt8]) {
            state.withLock {
                $0.count += 1
                $0.total += chunk.count
                $0.largest = max($0.largest, chunk.count)
            }
        }

        var counts: (count: Int, total: Int, largest: Int) { state.withLock(\.self) }

        deinit {
            // No teardown beyond ARC.
        }
    }

    /// Lets the serve loop, the handler child, and the producer take their turns between polls.
    private static func settle(rounds: Int) async throws {
        for _ in 0 ..< rounds {
            try await Task.sleep(for: .milliseconds(1))
        }
    }

    /// One keep-alive exchange over `connection`, threading the caller's buffer so its capacity can be
    /// read between requests — exactly what the connection retains for the rest of its life.
    private func serveOne(
        _ server: HTTPServer<ContinuousClock>,
        on connection: any TransportConnection,
        buffer: inout [UInt8],
        start: inout Int,
        responseBuffer: inout [UInt8]
    ) async -> Bool {
        await server.serveOne(
            connection,
            deadline: IdleDeadline<ContinuousClock.Instant>(),
            buffer: &buffer,
            start: &start,
            responseBuffer: &responseBuffer
        )
    }

    private func streamingRouter(_ log: ChunkLog) -> Router {
        Router {
            Route.post("/upload") { _, body, _ in
                for await chunk in body.asStream {
                    log.record(chunk)
                }
                return .text("ok")
            }
            .streamingBody()
            Route.get("/after") { _, _, _ in .text("AFTER") }
        }
    }

    @Test(
        "a 256 MiB content-length upload leaves the keep-alive buffer small",
        .timeLimit(.minutes(1)))
    func contentLengthUploadDoesNotRetainTheBody() async {
        let log = ChunkLog()
        let head = Array(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: \(Self.uploadSize)\r\n\r\n".utf8
        )
        let connection = SynthesizedUploadConnection(
            id: TransportConnectionID(1),
            head: head,
            bodyCount: Self.uploadSize,
            framing: .contentLength,
            tail: Array("GET /after HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: streamingRouter(log),
            limits: Self.streamingLimits
        )
        var buffer: [UInt8] = []
        var start = 0
        var responseBuffer: [UInt8] = []

        let keepAlive = await serveOne(
            server, on: connection, buffer: &buffer, start: &start, responseBuffer: &responseBuffer
        )
        #expect(keepAlive)
        #expect(log.counts.total == Self.uploadSize)  // the handler saw every octet
        // THE regression: the body must never have entered the connection's read buffer.
        #expect(buffer.capacity <= server.limits.keepAliveBufferCapacity)

        // The pipelined follow-up is still exactly aligned after a quarter gibibyte of body.
        _ = await serveOne(
            server, on: connection, buffer: &buffer, start: &start, responseBuffer: &responseBuffer
        )
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasSuffix("AFTER"))
        #expect(buffer.capacity <= server.limits.keepAliveBufferCapacity)
    }

    @Test(
        "a 256 MiB chunked upload streams in window-bounded chunks",
        .timeLimit(.minutes(1)))
    func chunkedUploadStreamsInBoundedChunks() async {
        let log = ChunkLog()
        let head = Array(
            "POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".utf8
        )
        let connection = SynthesizedUploadConnection(
            id: TransportConnectionID(1),
            head: head,
            bodyCount: Self.uploadSize,
            framing: .chunked(chunkSize: 1 << 20),
            tail: Array("GET /after HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: streamingRouter(log),
            limits: Self.streamingLimits
        )
        var buffer: [UInt8] = []
        var start = 0
        var responseBuffer: [UInt8] = []

        let keepAlive = await serveOne(
            server, on: connection, buffer: &buffer, start: &start, responseBuffer: &responseBuffer
        )
        #expect(keepAlive)
        let seen = log.counts
        #expect(seen.total == Self.uploadSize)
        #expect(seen.count > 1)  // it streamed, rather than arriving as one accumulated body
        // No decoded chunk may exceed the receive window it was framed inside.
        #expect(seen.largest <= server.limits.effectiveRequestBodyWindow)
        #expect(buffer.capacity <= server.limits.keepAliveBufferCapacity)

        _ = await serveOne(
            server, on: connection, buffer: &buffer, start: &start, responseBuffer: &responseBuffer
        )
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasSuffix("AFTER"))
    }

    @Test(
        "the producer suspends until the handler takes each chunk",
        .timeLimit(.minutes(1)))
    func producerParksUntilTheHandlerConsumes() async throws {
        let gate = AsyncGate()
        let router = Router {
            Route.post("/upload") { _, body, _ in
                var total = 0
                for await chunk in body.asStream {
                    try? await gate.waitUntilOpen()  // one permit per chunk taken
                    total += chunk.count
                }
                return .text("total \(total)")
            }
            .streamingBody()
        }
        let head = Array(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: \(Self.uploadSize)\r\n\r\n".utf8
        )
        let connection = SynthesizedUploadConnection(
            id: TransportConnectionID(1),
            head: head,
            bodyCount: Self.uploadSize,
            framing: .contentLength
        )
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: router,
            limits: Self.streamingLimits
        )
        let serving = Task { await server.serve(connection) }

        // The handler is provably parked, so the producer can be at most one handed-off chunk ahead of
        // it. HTTP/1.1 has no flow control: the ONLY backpressure is the producer suspending, which from
        // the wire looks like `receive` never being called again.
        try await gate.waitForWaiters(atLeast: 1)
        try await Self.settle(rounds: 20)  // let the producer reach its own park before sampling
        let parked = await connection.receiveCount
        try await Self.settle(rounds: 50)
        #expect(await connection.receiveCount == parked)
        // And it parked near the START of the upload, not after draining it: with one chunk in flight
        // the wire is at most a couple of windows in, against a quarter gibibyte of body.
        #expect(parked * server.limits.effectiveRequestBodyWindow <= 1 << 20)

        serving.cancel()
        _ = await serving.value
    }

    @Test(
        "a handler that abandons the body still drains the wire and keeps the pipeline aligned",
        .timeLimit(.minutes(1)))
    func abandonedBodyStillDrainsTheWire() async {
        let router = Router {
            Route.post("/upload") { _, _, _ in .text("IGNORED") }.streamingBody()
            Route.get("/after") { _, _, _ in .text("AFTER") }
        }
        let body = 4 << 20  // enough to span many reads without making the test slow
        let head = Array(
            "POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".utf8
        )
        let connection = SynthesizedUploadConnection(
            id: TransportConnectionID(1),
            head: head,
            bodyCount: body,
            framing: .chunked(chunkSize: 64 * 1_024),
            tail: Array("GET /after HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        let server = HTTPServer(transport: FakeTransport(), responder: router)
        var buffer: [UInt8] = []
        var start = 0
        var responseBuffer: [UInt8] = []

        #expect(
            await serveOne(
                server,
                on: connection,
                buffer: &buffer,
                start: &start,
                responseBuffer: &responseBuffer
            ))
        _ = await serveOne(
            server, on: connection, buffer: &buffer, start: &start, responseBuffer: &responseBuffer
        )
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.contains("IGNORED"))
        #expect(wire.hasSuffix("AFTER"))  // the abandoned body did not desync the follow-up
        #expect(await connection.isDrained)  // every octet was read off the wire, not skipped
        #expect(buffer.capacity <= server.limits.keepAliveBufferCapacity)
    }

    @Test(
        "a large buffered upload does not leave its peak capacity on the connection",
        .timeLimit(.minutes(1)))
    func bufferedUploadReleasesItsPeakCapacity() async {
        // The *buffered* path is the one that legitimately accumulates a body in the connection read
        // buffer — `frameBody` needs the whole thing to build a `ParsedRequest`. Streaming no longer
        // touches that buffer at all, so this is the only remaining way to leave a peak behind, and
        // `removeAll(keepingCapacity: true)` would hand it to every later request on the connection.
        let uploadSize = 8 << 20
        let router = Router {
            Route.post("/upload") { _, body, _ in .text("got \(await body.collect().count)") }
            Route.get("/after") { _, _, _ in .text("AFTER") }
        }
        let head = Array(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: \(uploadSize)\r\n\r\n".utf8
        )
        let connection = SynthesizedUploadConnection(
            id: TransportConnectionID(1),
            head: head,
            bodyCount: uploadSize,
            framing: .contentLength,
            tail: Array("GET /after HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        let server = HTTPServer(transport: FakeTransport(), responder: router)
        var buffer: [UInt8] = []
        var start = 0
        var responseBuffer: [UInt8] = []

        #expect(
            await serveOne(
                server,
                on: connection,
                buffer: &buffer,
                start: &start,
                responseBuffer: &responseBuffer
            ))
        // The peak itself is legitimate and expected — pinning it keeps this test honest about which
        // case it exercises.
        #expect(buffer.capacity > server.limits.keepAliveBufferCapacity)

        _ = await serveOne(
            server, on: connection, buffer: &buffer, start: &start, responseBuffer: &responseBuffer
        )
        #expect(buffer.capacity <= server.limits.keepAliveBufferCapacity)
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.contains("got \(uploadSize)"))
        #expect(wire.hasSuffix("AFTER"))
    }

    @Test(
        "a streamed chunked body over the route limit is refused mid-stream (RFC 9112 §7.1)",
        .timeLimit(.minutes(1)))
    func chunkedStreamedBodyStillHonorsTheRouteLimit() async {
        let log = ChunkLog()
        let cap = 128 * 1_024
        let router = Router {
            Route.post("/upload") { _, body, _ in
                for await chunk in body.asStream {
                    log.record(chunk)
                }
                return .text("ok")
            }
            .streamingBody()
            .bodyLimited(to: cap)
        }
        // A chunked body declares no length, so nothing can pre-reject it the way a Content-Length is
        // pre-rejected: the cap can only be enforced *while decoding*. And this driver hands every
        // decoded chunk onward and drops it, so the decoder's live buffer is empty at the top of every
        // pass — only its own monotonic count can still bound the body (CWE-409).
        let head = Array(
            "POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".utf8
        )
        let connection = SynthesizedUploadConnection(
            id: TransportConnectionID(1),
            head: head,
            bodyCount: 1 << 20,
            framing: .chunked(chunkSize: 32 * 1_024)
        )
        let server = HTTPServer(transport: FakeTransport(), responder: router)
        var buffer: [UInt8] = []
        var start = 0
        var responseBuffer: [UInt8] = []

        let keepAlive = await serveOne(
            server, on: connection, buffer: &buffer, start: &start, responseBuffer: &responseBuffer
        )
        #expect(!keepAlive)  // refused mid-stream: close rather than desync a pipelined follow-up
        #expect(log.counts.total <= cap)
        // It stopped reading at the cap instead of draining the whole megabyte first.
        #expect(await connection.receiveCount * server.limits.effectiveRequestBodyWindow < 1 << 20)
    }
}
