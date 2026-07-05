//
//  HTTP2ConcurrentDispatchTests.swift
//  HTTPServerTests
//
//  FIX #3 — HTTP/2 streams multiplexed on one connection are dispatched concurrently: each buffered
//  request's handler runs in its own child task, so a slow handler on one stream no longer stalls the
//  sibling streams in the same batch (application-layer head-of-line blocking). The engine and all frame
//  writes stay single-owner on the serve loop; only the handlers run off-loop, and each response is
//  flushed the instant its handler finishes (completion order, valid on independent streams — RFC 9113
//  §5). Driven over a ``ControllableConnection`` with a gate that pins one handler while the sibling is
//  observed answering.
//

import HPACK
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("FIX #3 — HTTP/2 concurrent stream dispatch (no application-layer head-of-line blocking)")
struct HTTP2ConcurrentDispatchTests {
    @Test(
        "a slow handler on one stream does not stall a sibling stream's response (TTFB ≈ 0)",
        .timeLimit(.minutes(1)))
    func slowHandlerDoesNotStallSibling() async throws {
        let slowGate = AsyncGate()  // /slow blocks here until the test releases it
        let router = Router {
            Route.get("/slow") { _, _, _ in
                try? await slowGate.waitUntilOpen()
                return .text("SLOW")
            }
            Route.get("/fast") { _, _, _ in .text("FAST") }
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router)
        let serving = Task { await server.serve(connection) }

        // One batch: preface + SETTINGS + HEADERS(stream 1 → /slow) + HEADERS(stream 3 → /fast). Both
        // requests arrive together, so the serve loop dispatches both handlers concurrently.
        await connection.feed(
            Self.preface + Self.settings()
                + Self.headers(streamID: 1, path: "/slow")
                + Self.headers(streamID: 3, path: "/fast")
        )

        // /fast (stream 3) must answer WHILE /slow (stream 1) is still gated — the proof there is no
        // head-of-line blocking. The old single serve loop `await`ed /slow to completion before it ever
        // reached /fast, so /fast's response would never appear here and the .timeLimit would fail.
        while !Self.hasResponse(onStream: 3, in: await connection.sentBytes()), !Task.isCancelled {
            await Task.yield()
        }
        #expect(Self.hasResponse(onStream: 3, in: await connection.sentBytes()))
        // /slow has NOT answered yet — it is still parked on the gate (TTFB for /fast ≈ 0, not ≈ /slow's).
        #expect(!Self.hasResponse(onStream: 1, in: await connection.sentBytes()))

        // Release /slow, end the connection, and confirm both streams ultimately answered.
        slowGate.open()
        await connection.finishInbound()
        await serving.value
        #expect(Self.hasResponse(onStream: 1, in: await connection.sentBytes()))
    }

    // The rewrite this suite guards: a merged mailbox (a `reader` task owns `connection.receive` in its
    // own continuous loop, decoupled from every handler) replaced a design where the serve loop's
    // per-batch `withTaskGroup` could not return — and so could not reach the NEXT `connection.receive()`
    // — until every handler task from THAT batch had finished. `slowHandlerDoesNotStallSibling` above
    // proves concurrency WITHIN one batch; this proves it ACROSS batches, which the old design did not
    // have: two requests arriving in separate TCP reads still serialized at the batch boundary.
    @Test(
        "a request in a SEPARATE later TCP read is not stalled behind an earlier read's slow handler (cross-batch dispatch)",
        .timeLimit(.minutes(1)))
    func slowHandlerInEarlierBatchDoesNotStallLaterBatch() async throws {
        let slowGate = AsyncGate()  // /slow blocks here until the test releases it
        let router = Router {
            Route.get("/slow") { _, _, _ in
                try? await slowGate.waitUntilOpen()
                return .text("SLOW")
            }
            Route.get("/fast") { _, _, _ in .text("FAST") }
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router)
        let serving = Task { await server.serve(connection) }

        // Batch 1 — its own `connection.feed`, i.e. its own `connection.receive()` return on the server
        // side: preface + SETTINGS + HEADERS(stream 1 → /slow).
        await connection.feed(Self.preface + Self.settings() + Self.headers(streamID: 1, path: "/slow"))
        // Deterministically wait until /slow's handler is provably parked on the gate — the point at
        // which the OLD loop's per-batch `withTaskGroup` could not have returned, so it could never have
        // reached the `connection.receive()` call that reads batch 2 below — before feeding batch 2.
        try await slowGate.waitForWaiters(atLeast: 1)

        // Batch 2 — a genuinely SEPARATE `connection.feed`: HEADERS(stream 3 → /fast).
        await connection.feed(Self.headers(streamID: 3, path: "/fast"))

        // /fast (stream 3, batch 2) must answer WHILE /slow (stream 1, batch 1) is still gated — proof
        // the reader reached batch 2 and /fast was dispatched without waiting for batch 1's handler.
        while !Self.hasResponse(onStream: 3, in: await connection.sentBytes()), !Task.isCancelled {
            await Task.yield()
        }
        #expect(Self.hasResponse(onStream: 3, in: await connection.sentBytes()))
        #expect(!Self.hasResponse(onStream: 1, in: await connection.sentBytes()))

        // Release /slow, end the connection, and confirm both streams ultimately answered.
        slowGate.open()
        await connection.finishInbound()
        await serving.value
        #expect(Self.hasResponse(onStream: 1, in: await connection.sentBytes()))
    }

    // Native-streaming responses used to share the residual head-of-line block too: the old pump called
    // `connection.receive()` itself while draining a `.stream` response's send-window backlog, so at
    // most one native-streaming response was ever in flight per connection (a second one collapsed to
    // buffered). This proves two concurrently-streaming responses now progress independently — neither
    // is required to reach completion before the other's first chunk (or, here, its whole body) appears.
    @Test(
        "two concurrently-streaming responses progress independently — neither blocks the other to completion",
        .timeLimit(.minutes(1)))
    func concurrentNativeStreamingResponsesDoNotBlockEachOther() async throws {
        let gateA = AsyncGate()  // /a's producer parks here after its first chunk
        let chunk1 = Array("first-".utf8)
        let chunk2 = Array("second".utf8)
        let router = Router {
            Route.get("/a") { _, _, _ in
                .streaming(contentType: "application/octet-stream") { writer in
                    try await writer.write(chunk1)
                    try? await gateA.waitUntilOpen()
                    try await writer.write(chunk2)
                }
            }
            Route.get("/b") { _, _, _ in
                .streaming(contentType: "application/octet-stream") { writer in
                    try await writer.write(chunk1)
                    try await writer.write(chunk2)
                }
            }
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: router)
        let serving = Task { await server.serve(connection) }

        // One batch: stream 1 → /a (gated after its first chunk), stream 3 → /b (never gated).
        await connection.feed(
            Self.preface + Self.settings()
                + Self.headers(streamID: 1, path: "/a")
                + Self.headers(streamID: 3, path: "/b")
        )

        // /b (stream 3) must complete its WHOLE body — both chunks, END_STREAM — while /a (stream 1) is
        // still stuck on its gate having sent only its FIRST chunk. Under the old one-stream-at-a-time
        // design this would deadlock (whichever of /a / /b did not win the single streaming slot would
        // buffer instead, and even if both happened to buffer-fallback, /a's OWN pump would still block
        // this test's `waitUntilOpen` from ever being reached first) — proof two relays now run at once.
        //
        // Two INDEPENDENT waits, not a single race: /a's and /b's request→relay→producer chains are
        // dispatched as separate child tasks with no ordering guarantee between them, so waiting for only
        // "/b has finished" and then immediately sampling /a's state is racy — it can observe /a's chain
        // BEFORE it has been scheduled at all (not "blocked", just "hasn't had a turn yet"), which looks
        // identical to a head-of-line block but isn't one. `gateA.waitForWaiters` proves /a's PRODUCER
        // offered chunk1 (see `AsyncHandoff.offer`'s doc — it can return before the relay/consumer have
        // actually pulled+flushed it), so also poll for chunk1 to physically reach the wire before
        // treating /a's side as settled; both waits are deterministic checkpoints, not a timing guess.
        try await gateA.waitForWaiters(atLeast: 1)
        while !Self.streamFinished(onStream: 3, in: await connection.sentBytes()), !Task.isCancelled {
            await Task.yield()
        }
        while Self.streamBody(onStream: 1, in: await connection.sentBytes()).isEmpty, !Task.isCancelled {
            await Task.yield()
        }
        let midway = await connection.sentBytes()
        #expect(Self.streamFinished(onStream: 3, in: midway))
        #expect(Self.streamBody(onStream: 3, in: midway) == chunk1 + chunk2)
        #expect(!Self.streamFinished(onStream: 1, in: midway))
        #expect(Self.streamBody(onStream: 1, in: midway) == chunk1)  // only the first chunk so far

        gateA.open()
        await connection.finishInbound()
        await serving.value
        let final = await connection.sentBytes()
        #expect(Self.streamFinished(onStream: 1, in: final))
        #expect(Self.streamBody(onStream: 1, in: final) == chunk1 + chunk2)
    }

    // MARK: Wire helpers (raw RFC 9113 frames)

    private static let preface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    private static func settings() -> [UInt8] {
        frame(type: 0x04, flags: 0, streamID: 0, payload: [])  // empty client SETTINGS
    }

    private static func headers(streamID: UInt32, path: String) -> [UInt8] {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = encoder.encode([
            HPACKField(name: ":method", value: "GET"),
            HPACKField(name: ":scheme", value: "http"),
            HPACKField(name: ":path", value: path),
            HPACKField(name: ":authority", value: "x")
        ])
        // HEADERS with END_HEADERS (0x04) | END_STREAM (0x01) — a complete GET, no body.
        return frame(type: 0x01, flags: 0x05, streamID: streamID, payload: block)
    }

    private static func frame(
        type: UInt8, flags: UInt8, streamID: UInt32, payload: [UInt8]
    ) -> [UInt8] {
        var out: [UInt8] = [
            UInt8(payload.count >> 16 & 0xFF), UInt8(payload.count >> 8 & 0xFF),
            UInt8(payload.count & 0xFF), type, flags,
            UInt8(streamID >> 24 & 0xFF), UInt8(streamID >> 16 & 0xFF),
            UInt8(streamID >> 8 & 0xFF), UInt8(streamID & 0xFF)
        ]
        out += payload
        return out
    }

    /// Whether the wire carries a HEADERS or DATA frame on `stream` — i.e. a server response began there.
    private static func hasResponse(onStream stream: UInt32, in bytes: [UInt8]) -> Bool {
        var index = 0
        while index + 9 <= bytes.count {
            let length =
                Int(bytes[index]) << 16 | Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
            let type = bytes[index + 3]
            let streamID =
                (UInt32(bytes[index + 5]) << 24 | UInt32(bytes[index + 6]) << 16
                    | UInt32(bytes[index + 7]) << 8 | UInt32(bytes[index + 8])) & 0x7FFF_FFFF
            guard index + 9 + length <= bytes.count else {
                break
            }
            if streamID == stream, type == 0x01 || type == 0x00 {  // HEADERS or DATA
                return true
            }
            index += 9 + length
        }
        return false
    }

    /// The concatenated DATA payload sent so far on `stream` (empty if none has arrived yet).
    private static func streamBody(onStream stream: UInt32, in bytes: [UInt8]) -> [UInt8] {
        var index = 0
        var data: [UInt8] = []
        while index + 9 <= bytes.count {
            let length =
                Int(bytes[index]) << 16 | Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
            let type = bytes[index + 3]
            let streamID =
                (UInt32(bytes[index + 5]) << 24 | UInt32(bytes[index + 6]) << 16
                    | UInt32(bytes[index + 7]) << 8 | UInt32(bytes[index + 8])) & 0x7FFF_FFFF
            let payloadStart = index + 9
            guard payloadStart + length <= bytes.count else {
                break
            }
            if type == 0x00, streamID == stream {  // DATA
                data += bytes[payloadStart ..< payloadStart + length]
            }
            index = payloadStart + length
        }
        return data
    }

    /// Whether a DATA frame carrying END_STREAM has arrived on `stream`.
    private static func streamFinished(onStream stream: UInt32, in bytes: [UInt8]) -> Bool {
        var index = 0
        while index + 9 <= bytes.count {
            let length =
                Int(bytes[index]) << 16 | Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
            let type = bytes[index + 3]
            let flags = bytes[index + 4]
            let streamID =
                (UInt32(bytes[index + 5]) << 24 | UInt32(bytes[index + 6]) << 16
                    | UInt32(bytes[index + 7]) << 8 | UInt32(bytes[index + 8])) & 0x7FFF_FFFF
            let payloadStart = index + 9
            guard payloadStart + length <= bytes.count else {
                break
            }
            if type == 0x00, streamID == stream, flags & 0x01 != 0 {  // DATA + END_STREAM
                return true
            }
            index = payloadStart + length
        }
        return false
    }
}
