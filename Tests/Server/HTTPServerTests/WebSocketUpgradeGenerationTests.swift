//
//  WebSocketUpgradeGenerationTests.swift
//  HTTPServerTests
//
//  Audit R5-SEC1b — a WebSocket upgrade resolves its handler from ITS OWN responder generation.
//
//  ``ResponderGenerationTests`` pins CR-F12 / finding 12 for ordinary requests: a request resolves its
//  route from the head, files a ``DispatchPlan``, and dispatches against the plan's snapshot, so a
//  ``HTTPServer/reloadResponder(_:)`` landing in between cannot pair one generation's body limit with
//  another's handler. Both Extended CONNECT paths (RFC 8441 §4 over HTTP/2, RFC 9220 over HTTP/3) were
//  the one shape that skipped the plan: they re-read the live snapshot at accept time, so a reload
//  between the CONNECT head and the upgrade handed the tunnel a handler from a table that never
//  admitted the request. That is finding 12 surviving on the upgrade path, and on a seam that makes an
//  authorization decision (``WebSocketHandler/shouldUpgrade(_:)``, CWE-807).
//
//  The race is STAGED, not hoped for. ``ResponderGenerationTests`` parks the serve loop mid-request by
//  withholding the body; a CONNECT has no body phase to park on — its head and its upgrade are two
//  moments of one event batch — so these drive the two moments by hand, through the very functions the
//  serve loops call, over harnesses (``H2Gate`` / ``H3Gate``) wired exactly as `serveHTTP2` /
//  `serveHTTP3` wire them. The reload goes between the two calls, which is deterministic where a
//  concurrent reload racing an actor hop would not be.
//
//  Both generations declare `/chat`, so a fallback to the live snapshot still *finds* a handler — it
//  finds the WRONG one. Asserting on which handler's `shouldUpgrade` ran is what distinguishes the two,
//  where a status code alone would not.
//

import HPACK
import HTTP2
import HTTP3
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Testing
import WebSocket

@testable import HTTPServer

@Suite("Audit R5-SEC1b — an Extended CONNECT upgrades on its own generation")
struct WebSocketUpgradeGenerationTests {
    private static var limits: HTTPLimits {
        HTTPLimits(
            streamReceiveWindow: H2ServerWire.maxFrame,
            connectionReceiveWindow: 1 << 20
        )
    }

    /// A router whose `/chat` WebSocket route reports `label` when the upgrade seam consults it.
    ///
    /// `shouldUpgrade` is the observation point on purpose: it is the exact call the upgrade makes on
    /// the handler it resolved, so recording there names the generation without inferring it.
    private static func generation(
        _ label: String,
        asked: AsyncEventProbe<String>
    ) -> Router {
        Router {
            Route.webSocket(
                "/chat",
                handler: ClosureWebSocketHandler(
                    shouldUpgrade: { _ in
                        asked.record(label)
                        return true
                    },
                    handle: { _ in [] }
                )
            )
        }
    }

    // MARK: HTTP/2 (RFC 8441)

    @Test(
        "HTTP/2: a reload between the CONNECT head and the upgrade keeps one generation",
        .timeLimit(.minutes(1)))
    func http2TunnelUpgradesOnTheHeadsGeneration() async throws {
        let asked = AsyncEventProbe<String>()
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Self.generation("A", asked: asked),
            limits: Self.limits
        )
        var state = try H2Gate.state(for: server, connectProtocol: true)
        let (wakeups, continuation) = AsyncStream.makeStream(
            of: HTTP2Wakeup.self, bufferingPolicy: .unbounded
        )

        // Moment one: the engine decodes the HEADERS and files generation A's plan for stream 1
        // (HTTP2Connection+Headers.swift calls `resolveRoute` before emitting `.extendedConnect`).
        let events = try state.engine.receive(
            H2ServerWire.extendedConnect(streamID: 1, path: "/chat")
        )
        #expect(state.plans.count == 1, "the head filed no plan — the harness is not wired")
        // The table is swapped in the window between the two moments.
        server.reloadResponder(Self.generation("B", asked: asked))
        // Moment two: the consumer accepts the tunnel.
        for event in events {
            await server.handleHTTP2Tunnel(event, state: &state, into: continuation)
        }

        // Generation A's handler authorized the upgrade; generation B's was never consulted.
        #expect(asked.events == ["A"])
        // And it was accepted, not refused — RFC 8441 §5's `200`, no END_STREAM.
        #expect(H2ServerWire.status(onStream: 1, in: state.engine.outboundBytes()) == "200")
        #expect(state.webSockets[HTTP2StreamID(1)] != nil)

        await state.endAllTunnels()
        await state.tasks.shutdown()
        continuation.finish()
        for await _ in wakeups {
            // Drain so the pump's yields do not outlive the test.
        }
    }

    @Test(
        "HTTP/2: an Extended CONNECT whose head filed no plan is refused, not re-resolved",
        .timeLimit(.minutes(1)))
    func http2TunnelWithoutAPlanIsRefused() async throws {
        // The fail-closed half: with no plan there is no generation, and falling back to the live
        // snapshot is the bug. `/chat` routes on the live table, so a fallback would answer `200`.
        let asked = AsyncEventProbe<String>()
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Self.generation("A", asked: asked),
            limits: Self.limits
        )
        var state = try H2Gate.state(for: server, connectProtocol: true)
        let (wakeups, continuation) = AsyncStream.makeStream(
            of: HTTP2Wakeup.self, bufferingPolicy: .unbounded
        )

        let events = try state.engine.receive(
            H2ServerWire.extendedConnect(streamID: 1, path: "/chat")
        )
        // The plan is dropped out from under the event — the state the fallback used to paper over.
        state.plans.remove(HTTP2StreamID(1))
        for event in events {
            await server.handleHTTP2Tunnel(event, state: &state, into: continuation)
        }
        continuation.finish()
        for await _ in wakeups {
            // No wakeup is expected from a refusal; drain so nothing outlives the test.
        }

        let sent = state.engine.outboundBytes()
        // RFC 9110 §15.6.1 — the server, not the request, is at fault.
        #expect(H2ServerWire.status(onStream: 1, in: sent) == "500")
        // Answered and retired like every other refusal (RFC 9113 §8.1 — RST_STREAM(NO_ERROR)).
        #expect(H2ServerWire.resetCode(onStream: 1, in: sent) == 0x00)
        #expect(!state.engine.isStreamOpen(HTTP2StreamID(1)))
        #expect(asked.isEmpty, "no handler should have been consulted at all")
    }

    // MARK: HTTP/3 (RFC 9220)

    @Test(
        "HTTP/3: a reload between the CONNECT head and the upgrade keeps one generation",
        .timeLimit(.minutes(1)))
    func http3TunnelUpgradesOnTheHeadsGeneration() async throws {
        let asked = AsyncEventProbe<String>()
        let server = HTTPServer(
            transport: try TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake)),
            responder: Self.generation("A", asked: asked)
        )
        let quic = FakeQUICConnection()
        let scope = H3Gate.scope(for: server, quic: quic, connectProtocol: true)
        let stream = FakeQUICStream(id: QUICStreamID(0), direction: .bidirectional)
        scope.registry.register(stream)

        // Moment one: the field section decodes and files generation A's plan
        // (HTTP3Connection+Request.swift calls `resolveRoute` before marking the stream a tunnel).
        let events = await server.receiveHTTP3(
            stream.id, Self.h3ExtendedConnect(path: "/chat"), fin: false, in: scope
        )
        #expect(scope.registry.plan(for: stream.id) != nil, "the head filed no plan")
        // The table is swapped in the window between the two moments.
        server.reloadResponder(Self.generation("B", asked: asked))
        // Moment two: the stream driver accepts the tunnel.
        var webSocket: WebSocketConnection?
        var tunnelHandler: (any WebSocketHandler)?
        for event in events {
            await server.handleHTTP3TunnelEvent(
                event,
                stream: stream,
                in: scope,
                webSocket: &webSocket,
                tunnelHandler: &tunnelHandler
            )
        }

        #expect(asked.events == ["A"])
        #expect(webSocket != nil, "the tunnel was refused")
        #expect(tunnelHandler != nil)
        #expect(stream.resetCodes.isEmpty)
    }

    @Test(
        "HTTP/3: an Extended CONNECT whose head filed no plan is refused, not re-resolved",
        .timeLimit(.minutes(1)))
    func http3TunnelWithoutAPlanIsRefused() async throws {
        let asked = AsyncEventProbe<String>()
        let server = HTTPServer(
            transport: try TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake)),
            responder: Self.generation("A", asked: asked)
        )
        let quic = FakeQUICConnection()
        let scope = H3Gate.scope(for: server, quic: quic, connectProtocol: true)
        let stream = FakeQUICStream(id: QUICStreamID(0), direction: .bidirectional)
        scope.registry.register(stream)

        let events = await server.receiveHTTP3(
            stream.id, Self.h3ExtendedConnect(path: "/chat"), fin: false, in: scope
        )
        // The registry entry — and with it the plan — goes before the event is applied.
        scope.registry.retire(stream.id)
        scope.registry.register(stream)
        var webSocket: WebSocketConnection?
        var tunnelHandler: (any WebSocketHandler)?
        for event in events {
            await server.handleHTTP3TunnelEvent(
                event,
                stream: stream,
                in: scope,
                webSocket: &webSocket,
                tunnelHandler: &tunnelHandler
            )
        }

        #expect(webSocket == nil, "a plan-less CONNECT must not open a tunnel")
        #expect(asked.isEmpty, "no handler should have been consulted at all")
        // RFC 9114 §8.1 H3_INTERNAL_ERROR (0x0102) — not H3_REQUEST_REJECTED: the request was not
        // rejected on its merits, the server lost track of which table owns it.
        #expect(stream.resetCodes == [HTTP3ErrorCode.h3InternalError.rawValue])
    }

    // MARK: - Wire helpers

    /// An h3 HEADERS frame (RFC 9114 §7.2.2) carrying an Extended CONNECT for `path` (RFC 9220).
    private static func h3ExtendedConnect(path: String) -> [UInt8] {
        let section = QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: "CONNECT"),
                HeaderField(name: ":protocol", value: "websocket"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "example.com"),
                HeaderField(name: ":path", value: path)
            ])
        var out: [UInt8] = []
        QUICVarint.encode(0x01, into: &out)
        QUICVarint.encode(UInt64(section.count), into: &out)
        out.append(contentsOf: section)
        return out
    }
}
