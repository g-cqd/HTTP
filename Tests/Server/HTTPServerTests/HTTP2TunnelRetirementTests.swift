//
//  HTTP2TunnelRetirementTests.swift
//  HTTPServerTests
//
//  The fifth review's R5-P0e: an RFC 8441 tunnel stream that does not become a tunnel must still end
//  like every other stream.
//
//  A denied Extended CONNECT — the wrong `:protocol`, no matching WebSocket route, a handler that
//  declined, a disallowed `Origin` — simply `return`ed. The engine had already opened the stream when
//  it decoded the HEADERS, so the peer was left waiting on a stream that would never answer and the
//  slot stayed charged against `maxConcurrentStreams` (RFC 9113 §5.1.2) for the rest of the
//  connection's life. Repeat it and the connection refuses every further stream while doing nothing.
//
//  A peer-ENDED tunnel leaked the same slot for the mirror reason: the driver treated END_STREAM from
//  the peer as needing nothing from the engine, so the server never sent its own END_STREAM and the
//  record stayed half-closed forever. RFC 8441 §5 says a tunnel's orderly close IS the END_STREAM
//  flag; RFC 9113 §5.1 is what turns "half-closed (remote)" into "closed" when the server sends one.
//
//  Everything here asserts against the ENGINE's own accounting (`isStreamOpen`), not a driver-side map:
//  the slot is the engine's stream record, and a driver map returning to zero says nothing about it.
//

import HPACK
import HTTP2
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing
import WebSocket

@testable import HTTPServer

@Suite("Audit R5-P0e — an HTTP/2 tunnel stream always retires")
struct HTTP2TunnelRetirementTests {
    /// One way an Extended CONNECT can be denied, and the answer RFC 9110 §15 gives the peer.
    struct Refusal: CustomTestStringConvertible {
        let label: String
        let proto: String
        let path: String
        let origin: String?
        let status: String

        var testDescription: String { label }
    }

    private static let refusals: [Refusal] = [
        Refusal(
            label: "unsupported :protocol",
            proto: "mqtt",
            path: "/chat",
            origin: nil,
            status: "501"
        ),
        Refusal(
            label: "no WebSocket route",
            proto: "websocket",
            path: "/nowhere",
            origin: nil,
            status: "404"
        ),
        Refusal(
            label: "handler declined",
            proto: "websocket",
            path: "/declined",
            origin: nil,
            status: "403"
        ),
        Refusal(
            label: "disallowed Origin",
            proto: "websocket",
            path: "/chat",
            origin: "https://evil.example",
            status: "403"
        )
    ]

    private static var limits: HTTPLimits {
        HTTPLimits(
            streamReceiveWindow: H2ServerWire.maxFrame,
            connectionReceiveWindow: 1 << 20
        )
    }

    private static var router: Router {
        Router {
            Route.webSocket("/chat", handler: ClosureWebSocketHandler { _ in [] })
            Route.webSocket(
                "/declined",
                handler: ClosureWebSocketHandler(
                    shouldUpgrade: { _ in false },
                    handle: { _ in [] }
                )
            )
        }
    }

    @Test(
        "a denied Extended CONNECT answers the peer and gives the slot back",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)),
        arguments: refusals)
    func refusedTunnelRetiresItsStream(refusal: Refusal) async throws {
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Self.router,
            limits: Self.limits
        )
        var state = try H2Gate.state(for: server, connectProtocol: true)
        let (wakeups, continuation) = AsyncStream.makeStream(
            of: HTTP2Wakeup.self, bufferingPolicy: .unbounded
        )

        let events = try state.engine.receive(
            H2ServerWire.extendedConnect(
                streamID: 1, path: refusal.path, proto: refusal.proto, origin: refusal.origin
            )
        )
        // The engine opened the stream when it decoded the HEADERS: the slot is charged before the
        // driver ever sees the event, which is why the driver has to give it back.
        #expect(state.engine.isStreamOpen(HTTP2StreamID(1)))
        for event in events {
            await server.handleHTTP2Tunnel(event, state: &state, into: continuation)
        }
        continuation.finish()
        for await _ in wakeups {
            // No wakeup is expected from a refusal; drain so the stream does not outlive the test.
        }

        let sent = state.engine.outboundBytes()
        // A definite answer, not silence.
        #expect(H2ServerWire.status(onStream: 1, in: sent) == refusal.status)
        // RFC 9113 §8.1: a complete response, then RST_STREAM(NO_ERROR) to release the stream.
        #expect(H2ServerWire.resetCode(onStream: 1, in: sent) == 0x00)
        // The engine's own accounting — the slot is back.
        #expect(!state.engine.isStreamOpen(HTTP2StreamID(1)))
        #expect(state.webSockets.isEmpty)
        #expect(state.tasks.isEmpty)
    }

    @Test(
        "refusals do not permanently consume the concurrency cap",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
    func refusalsDoNotExhaustTheStreamCap() async throws {
        // The consequence, stated as the peer experiences it: with a cap of one, a refused Extended
        // CONNECT must not stop the next stream being admitted (RFC 9113 §5.1.2).
        let capped = HTTPLimits.default.with { $0.maxConcurrentStreams = 1 }
        let server = HTTPServer(transport: FakeTransport(), responder: Self.router, limits: capped)
        var state = try H2Gate.state(for: server, connectProtocol: true)
        let (wakeups, continuation) = AsyncStream.makeStream(
            of: HTTP2Wakeup.self, bufferingPolicy: .unbounded
        )

        for event in try state.engine.receive(
            H2ServerWire.extendedConnect(streamID: 1, path: "/nowhere")
        ) {
            await server.handleHTTP2Tunnel(event, state: &state, into: continuation)
        }
        _ = state.engine.outboundBytes()
        // A plain request on the next stream: refused with RST_STREAM(REFUSED_STREAM) while the
        // withdrawn tunnel still holds the only slot, and served once it has been given back.
        let admitted = try state.engine.receive(
            H2ServerWire.headers(streamID: 3, method: "GET", path: "/chat", endStream: true)
        )
        continuation.finish()
        for await _ in wakeups {
            // Drain; nothing is under assertion here.
        }

        #expect(!admitted.isEmpty, "stream 3 was refused — the tunnel slot was never returned")
        #expect(H2ServerWire.resetCode(onStream: 3, in: state.engine.outboundBytes()) == nil)
    }

    @Test(
        "a peer-ended tunnel gives its slot back",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
    func peerEndedTunnelRetiresItsStream() async throws {
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Self.router,
            limits: Self.limits
        )
        var state = try H2Gate.state(for: server, connectProtocol: true)
        let (wakeups, continuation) = AsyncStream.makeStream(
            of: HTTP2Wakeup.self, bufferingPolicy: .unbounded
        )
        let connection = ControllableConnection(alpn: "h2")

        for event in try state.engine.receive(
            H2ServerWire.extendedConnect(streamID: 1, path: "/chat")
        ) {
            await server.handleHTTP2Tunnel(event, state: &state, into: continuation)
        }
        #expect(state.engine.isStreamOpen(HTTP2StreamID(1)))
        // The peer closes its half of the tunnel — RFC 8441 §5's orderly close.
        for event in try state.engine.receive(
            H2ServerWire.data(streamID: 1, payload: [], endStream: true)
        ) {
            await server.handleHTTP2Tunnel(event, state: &state, into: continuation)
        }
        _ = state.engine.outboundBytes()

        let closed = await withDiscardingTaskGroup(returning: Bool.self) { group in
            let close = await server.applyHTTP2Wakeup(
                .tunnelEnded(HTTP2StreamID(1)),
                state: &state,
                group: &group,
                connection: connection,
                intake: BoundedByteChannel(
                    highWatermark: 1_024, lowWatermark: 512, maxQueuedChunks: 4, coalescingBelow: 0
                ),
                sendDeadline: IdleDeadline(in: DeadlineWheel(), escalation: .keepWatching),
                into: continuation
            )
            group.cancelAll()
            return close
        }
        continuation.finish()
        for await _ in wakeups {
            // Drain; nothing is under assertion here.
        }

        _ = closed
        // The server answered the peer's END_STREAM with its own, which is what closes the stream
        // (RFC 9113 §5.1: half-closed (remote) → closed) and hands the slot back.
        #expect(H2ServerWire.isFinished(onStream: 1, in: await connection.sentBytes()))
        #expect(!state.engine.isStreamOpen(HTTP2StreamID(1)))
        #expect(state.tasks.isEmpty)
    }
}
