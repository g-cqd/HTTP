//
//  HTTPServerHTTP3RetirementFunnelTests.swift
//  HTTPServerTests
//
//  R5-P0c, first property — one funnel.
//
//  ``HTTP3Connection`` is sans-I/O: resetting a QUIC stream on the wire and dropping the registry entry
//  tells it nothing at all. So *every* way a request stream can end abnormally has to converge on the
//  same retirement, or the paths that do not converge each leak the stream's parser buffer, its decoded
//  request, its buffered body against the connection-wide budget (RFC 9114 §4.1), its slot in the
//  SETTINGS_QPACK_BLOCKED_STREAMS allowance (RFC 9204 §2.1.2), its armed read deadline, and the RFC 9114
//  §8.1 abuse charge the abandonment was supposed to cost the peer.
//
//  Three rounds of point fixes covered the exits their own tests happened to drive — the deadline lapse,
//  then the truncated upload — and left the rest. So these tests deliberately do NOT assert per-exit
//  behaviour. Every case runs the SAME census assertion: whatever the exit, the connection engine comes
//  back to the census it had before the stream existed. A new exit path that forgets to retire fails
//  here without anybody having to remember to add an assertion for it.
//
//  Standards: RFC 9114 §4.1, §6.2, §8.1; RFC 9204 §2.1.2; RFC 9220 §3; CWE-770, CWE-400.
//

import HTTP3
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Synchronization
import Testing
import WebSocket

@testable import HTTPServer

@Suite("HTTP/3 — every abnormal exit retires the same state (R5-P0c)")
struct HTTPServerHTTP3RetirementFunnelTests {
    private typealias Server = HTTPServer<TestClock>

    private static let requestStream = QUICStreamID(0)
    private static let encoderStream = QUICStreamID(6)

    /// The ways a request stream can end without a response, each of which bypassed some part of the
    /// common retirement before this change.
    enum AbnormalExit: String, CaseIterable, Sendable {
        /// The transport fails mid-request — `receive()` throws rather than returning EOF.
        case receiveFailure
        /// The peer hangs up mid-body without a FIN.
        case eofMidBody
        /// An Extended CONNECT the server refuses (RFC 9220 §3 / RFC 6455 §10.2 origin check).
        case rejectedTunnel
        /// The read deadline lapses on a stream that opened and stalled (RFC 9112 §9.3 over §4.1).
        case deadlineLapse
    }

    @Test(
        "the engine returns to its baseline census however the stream ends",
        arguments: AbnormalExit.allCases
    )
    func everyAbnormalExitRetiresTheEngine(_ exit: AbnormalExit) async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let server = try Self.makeServer(clock: clock)
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        let engine = try await Self.engine(of: server)
        let baseline = await engine.census()
        #expect(baseline == Self.emptyCensus(), "nothing is tracked before a stream opens")

        let stream = FakeQUICStream(
            id: Self.requestStream,
            direction: .bidirectional,
            inbound: [(Self.opening(for: exit), false)]
        )
        quic.accept(stream)

        switch exit {
            case .receiveFailure, .eofMidBody, .deadlineLapse:
                // The stream really is loaded before it is abandoned — otherwise a census that is
                // already empty proves nothing at all.
                try await Self.settle { await engine.census().trackedStreams == 1 }
                if exit == .receiveFailure { stream.failInbound() }
                if exit == .eofMidBody { stream.finishInbound() }
                if exit == .deadlineLapse {
                    try await Self.advance(clock, by: .seconds(31), times: 40) {
                        !stream.resetCodes.isEmpty
                    }
                }
            case .rejectedTunnel:
                // The refusal follows the CONNECT within one engine step, so there is no window in
                // which the tunnel record is observable; the reset is what says it was recorded and
                // then given up on (RFC 9220 §3).
                try await Self.settle { !stream.resetCodes.isEmpty }
        }

        try await Self.settle { await engine.census().trackedStreams == 0 }
        let retired = await engine.census()
        #expect(retired.trackedStreams == baseline.trackedStreams)
        #expect(retired.blockedSections == baseline.blockedSections)
        #expect(retired.bufferedRequestBodyBytes == baseline.bufferedRequestBodyBytes)
        // Abandoning a stream has to cost the peer something, or repeating it is free — which is the
        // whole point of routing every exit through `resetStream` rather than a bespoke cleanup
        // (RFC 9114 §8.1, CVE-2023-44487 / CVE-2025-8671 parity).
        #expect(retired.chargedStreamResets > baseline.chargedStreamResets)
        #expect(!stream.resetCodes.isEmpty, "the peer is told, not left waiting")
        let deadlines = try #require(Self.scope(of: server)).deadlines
        #expect(deadlines.isEmpty, "the read deadline is disarmed with everything else")
    }

    @Test("a refused routed batch retires its stream through the same funnel")
    func mailboxOverflowRetiresTheEngine() async throws {
        // Overflow is the one exit whose interleaving a full connection cannot be made to produce on
        // demand, so it is driven at the driver seam every read path shares — the same
        // `receiveHTTP3`, the same funnel, the same census oracle.
        let server = try Self.makeServer(clock: TestClock())
        let quic = FakeQUICConnection()
        let scope = Self.makeScope(quic: quic, mailboxByteBudget: 1)
        let request = FakeQUICStream(id: Self.requestStream, direction: .bidirectional)
        scope.registry.register(request)

        // The peer's encoder stream opens first, so it is part of the baseline rather than part of
        // what has to be retired: RFC 9114 §6.2 streams are long-lived and never retired.
        _ = await scope.engine.receive(
            Self.encoderStream,
            [0x02],
            fin: false,
            routingInto: scope.registry
        )
        let baseline = await scope.engine.census()

        // A blocked request (RFC 9204 §2.1.2) whose mailbox is already occupied, so the batch the
        // encoder's insert routes to it cannot fit and must be refused rather than dropped.
        _ = await scope.engine.receive(
            Self.requestStream,
            Self.headersFrame(Self.blockedFieldSection),
            fin: true,
            routingInto: scope.registry
        )
        _ = scope.registry.deposit(
            [.requestEnd(streamID: Self.requestStream)],
            for: Self.requestStream
        )
        #expect(await scope.engine.census().blockedSections == 1)

        _ = await server.receiveHTTP3(
            Self.encoderStream,
            Self.insertAuthority,
            fin: false,
            in: scope
        )

        let retired = await scope.engine.census()
        #expect(retired.trackedStreams == baseline.trackedStreams, "the refused record is retired")
        #expect(retired.blockedSections == baseline.blockedSections)
        #expect(retired.bufferedRequestBodyBytes == baseline.bufferedRequestBodyBytes)
        #expect(retired.chargedStreamResets == baseline.chargedStreamResets + 1)
        #expect(request.resetCodes == [HTTP3ErrorCode.h3ExcessiveLoad.rawValue])
        #expect(scope.registry.isEmpty)
    }

    @Test("input queued for a stream retired mid-flight does not bring it back")
    func lateInputDoesNotResurrectARetiredStream() async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let server = try Self.makeServer(clock: clock)
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        let engine = try await Self.engine(of: server)
        let stream = FakeQUICStream(
            id: Self.requestStream,
            direction: .bidirectional,
            inbound: [(Self.partialRequest(), false)]
        )
        quic.accept(stream)
        try await Self.settle { await engine.census().trackedStreams == 1 }

        try await Self.advance(clock, by: .seconds(31), times: 40) { !stream.resetCodes.isEmpty }
        try await Self.settle { await engine.census().trackedStreams == 0 }
        let charged = await engine.census().chargedStreamResets

        // The octets that were still in flight when the reaper fired now reach the engine. A record
        // rebuilt here would be a retired stream coming back with a fresh share of every budget.
        _ = await server.receiveHTTP3(
            Self.requestStream,
            Self.partialRequest(),
            fin: false,
            in: try #require(Self.scope(of: server))
        )

        let after = await engine.census()
        #expect(after == Self.emptyCensus(charging: charged))
    }

    // MARK: - Fixtures

    /// The census of a connection holding nothing at all, with `charged` resets on the §8.1 budget.
    private static func emptyCensus(charging charged: Int = 0) -> HTTP3ConnectionCensus {
        HTTP3ConnectionCensus(
            trackedStreams: 0,
            blockedSections: 0,
            bufferedRequestBodyBytes: 0,
            chargedStreamResets: charged
        )
    }

    /// The opening octets that load the stream for `exit` — enough real state that an un-retired
    /// engine is visibly non-empty afterwards.
    private static func opening(for exit: AbnormalExit) -> [UInt8] {
        switch exit {
            case .rejectedTunnel:
                Self.headersFrame(Self.extendedConnectSection)
            case .receiveFailure, .eofMidBody, .deadlineLapse:
                Self.partialRequest()
        }
    }

    /// A server with a WebSocket route that refuses every origin, so an Extended CONNECT is rejected
    /// after the engine has already recorded the tunnel (RFC 9220 §3, RFC 6455 §10.2).
    private static func makeServer(clock: TestClock) throws -> Server {
        let limits = HTTPLimits.default.with {
            $0.headerReadTimeout = .seconds(30)
            $0.idleTimeout = .seconds(30)
            $0.keepAliveTimeout = .seconds(30)
        }
        let router = Router {
            Route.webSocket("/chat", handler: RefusingWebSocketHandler())
            Route.get("/") { _, _, _ in .text("ok") }
        }
        return HTTPServer(
            transport: try TransportFactory.make(
                TransportConfiguration(port: 0, backbone: .fake)
            ),
            responder: router,
            limits: limits,
            clock: clock
        )
    }

    /// A connection scope wired by hand, for the exits a live connection cannot be made to schedule.
    private static func makeScope(
        quic: FakeQUICConnection,
        mailboxByteBudget: Int
    ) -> Server.HTTP3ConnectionScope {
        let unmatched: @Sendable (QUICStreamID, HTTPRequest) -> RequestBodyPolicy = { _, _ in
            .unmatched
        }
        return Server.HTTP3ConnectionScope(
            quic: quic,
            registry: HTTP3StreamRegistry(mailboxByteBudget: mailboxByteBudget),
            engine: Server.Engine(
                limits: .default,
                enableConnectProtocol: false,
                resolveRoute: unmatched
            ),
            deadlines: HTTP3StreamDeadlines()
        )
    }

    private static func scope(of server: Server) -> Server.HTTP3ConnectionScope? {
        server.activeQUICConnections.withLock(\.values.first)
    }

    private static func engine(of server: Server) async throws -> Server.Engine {
        try await Self.settle { server.liveHTTP3ConnectionCount == 1 }
        return try #require(Self.scope(of: server)).engine
    }

    /// A complete HEADERS frame followed by a DATA prefix and no FIN (RFC 9114 §4.1).
    private static func partialRequest() -> [UInt8] {
        let section = QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: "POST"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "example.com"),
                HeaderField(name: ":path", value: "/")
            ])
        var out = Self.headersFrame(section)
        let body = [UInt8](repeating: 0x61, count: 32)
        QUICVarint.encode(0x00, into: &out)
        QUICVarint.encode(UInt64(body.count), into: &out)
        out.append(contentsOf: body)
        return out
    }

    /// An Extended CONNECT field section (RFC 9220 §3 / RFC 8441 §4).
    private static var extendedConnectSection: [UInt8] {
        QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: "CONNECT"),
                HeaderField(name: ":protocol", value: "websocket"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "example.com"),
                HeaderField(name: ":path", value: "/chat")
            ])
    }

    /// A request field section with prefix RIC=1/Base=0 whose `:authority` is a dynamic reference.
    private static let blockedFieldSection: [UInt8] = [0x02, 0x00, 0xD1, 0xD7, 0xC1, 0x80]

    /// The encoder-stream instruction inserting `:authority: dyn.example`.
    private static var insertAuthority: [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(0, prefixBits: 6, firstByte: 0xC0, into: &out)
        QPACKString.encode(Array("dyn.example".utf8), prefixBits: 7, into: &out)
        return out
    }

    /// A HEADERS frame (RFC 9114 §7.2.2) carrying `section`.
    private static func headersFrame(_ section: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        QUICVarint.encode(0x01, into: &out)
        QUICVarint.encode(UInt64(section.count), into: &out)
        out.append(contentsOf: section)
        return out
    }

    private static func advance(
        _ clock: TestClock,
        by step: Duration,
        times: Int,
        until condition: @Sendable () -> Bool
    ) async throws {
        for _ in 0 ..< times where !condition() {
            clock.advance(by: step)
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(condition(), "advance budget exhausted with the condition still false")
    }

    private static func settle(until condition: @Sendable () async -> Bool) async throws {
        for _ in 0 ..< 200 {
            if await condition() {
                return
            }
            try await Task.sleep(for: .milliseconds(5))
        }
        let satisfied = await condition()
        #expect(satisfied, "settle budget exhausted with the condition still false")
    }
}
