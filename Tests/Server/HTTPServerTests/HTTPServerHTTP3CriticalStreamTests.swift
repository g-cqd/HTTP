//
//  HTTPServerHTTP3CriticalStreamTests.swift
//  HTTPServerTests
//
//  RFC 9114 §6.2 — the control and QPACK encoder/decoder streams are long-lived by design. They stay
//  open for the whole connection and are *idle* whenever no settings or table updates flow, which on a
//  quiet connection is almost always. They are not request streams and they carry no request, so none
//  of the RFC 9112 §9.3 Slowloris budgets a request stream is bounded by can apply to them.
//
//  Audit addendum P0.5 armed a read deadline on every inbound QUIC stream, critical ones included, so a
//  connection whose peer simply had nothing to say had its control and QPACK streams reset out from
//  under it after `headerReadTimeout`. That is the defense terminating the healthy connection.
//
//  And when a critical stream really does end, RFC 9114 §6.2.1 says it is a *connection* error of type
//  H3_CLOSED_CRITICAL_STREAM — the opposite of the routine per-stream reset the reaper was issuing.
//
//  Standards: RFC 9114 §6.2, §6.2.1, §8.1; RFC 9204 §2.1.2, §4.2.
//

import HTTP3
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Synchronization
import Testing

@testable import HTTPServer

@Suite("HTTP/3 — critical streams are long-lived, not deadline-bounded (RFC 9114 §6.2)")
struct HTTPServerHTTP3CriticalStreamTests {
    private typealias Server = HTTPServer<TestClock>

    /// The peer's three critical unidirectional streams (RFC 9114 §6.2 / RFC 9204 §4.2), by the
    /// client-initiated unidirectional ids QUIC would mint for them (RFC 9000 §2.1).
    private static let peerControl = QUICStreamID(2)
    private static let peerEncoder = QUICStreamID(6)
    private static let peerDecoder = QUICStreamID(10)
    private static let requestStream = QUICStreamID(0)

    @Test("a critical stream idle past every deadline is never reset and keeps serving")
    func idleCriticalStreamsSurviveEveryDeadline() async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let handled = AsyncEventProbe<String>()
        let server = try Self.makeServer(clock: clock, handled: handled)
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        let critical = Self.acceptCriticalStreams(on: quic)
        let engine = try await Self.engine(of: server)
        // All three are classified and tracked before the clock moves, so the advance below really is
        // an *idle* critical stream and not a race with its first octets.
        try await Self.settle { await engine.census().trackedStreams == critical.count }

        // Well past `headerReadTimeout` and `idleTimeout` both, in the same steps the watchdog wakes on.
        try await Self.advance(clock, by: .seconds(31), times: 20)

        for stream in critical {
            #expect(stream.resetCodes.isEmpty, "a long-lived §6.2 stream must not be reaped")
        }
        #expect(quic.closeCodes.isEmpty, "an idle critical stream is not a connection fault")

        // And the connection is still *serving*: a request whose QPACK section is blocked on a dynamic
        // insert (RFC 9204 §2.1.2) is answered only if the peer's encoder stream survived the advance.
        let request = FakeQUICStream(
            id: Self.requestStream,
            direction: .bidirectional,
            inbound: [(Self.headersFrame(Self.blockedFieldSection), true)]
        )
        quic.accept(request)
        try await Self.settle { await engine.census().blockedSections == 1 }
        critical[1].deliver(Self.insertAuthority, fin: false)

        _ = try await handled.wait(forAtLeast: 1)
        try await Self.settle { request.sendCount > 0 }
        #expect(handled.count == 1)
    }

    @Test("the peer closing a critical stream is a connection error, not a stream reset")
    func closingACriticalStreamClosesTheConnection() async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let server = try Self.makeServer(clock: clock, handled: AsyncEventProbe())
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        let critical = Self.acceptCriticalStreams(on: quic)
        let engine = try await Self.engine(of: server)
        try await Self.settle { await engine.census().trackedStreams == critical.count }

        // RFC 9114 §6.2.1 — "If either control stream is closed at any point, this MUST be treated as a
        // connection error of type H3_CLOSED_CRITICAL_STREAM."
        critical[0].deliver([], fin: true)

        try await Self.settle { !quic.closeCodes.isEmpty }
        #expect(quic.closeCodes == [HTTP3ErrorCode.h3ClosedCriticalStream.rawValue])
        #expect(
            critical[0].resetCodes.isEmpty,
            "§6.2.1 escalates to the connection, not the stream"
        )
    }

    @Test("a peer critical stream that ends without FIN is still a connection error")
    func aCriticalStreamEndingAtEOFClosesTheConnection() async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let server = try Self.makeServer(clock: clock, handled: AsyncEventProbe())
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        let critical = Self.acceptCriticalStreams(on: quic)
        let engine = try await Self.engine(of: server)
        try await Self.settle { await engine.census().trackedStreams == critical.count }

        // A transport EOF is a closure too: §6.2.1 does not distinguish how the stream ended.
        critical[0].finishInbound()

        try await Self.settle { !quic.closeCodes.isEmpty }
        #expect(quic.closeCodes == [HTTP3ErrorCode.h3ClosedCriticalStream.rawValue])
    }

    // MARK: - Fixtures

    /// Opens the peer's control + QPACK encoder + decoder streams with their §6.2 preambles.
    private static func acceptCriticalStreams(on quic: FakeQUICConnection) -> [FakeQUICStream] {
        let streams = [
            FakeQUICStream(
                id: Self.peerControl,
                direction: .unidirectional,
                inbound: [(Self.controlPreamble, false)]
            ),
            FakeQUICStream(
                id: Self.peerEncoder,
                direction: .unidirectional,
                inbound: [([0x02], false)]
            ),
            FakeQUICStream(
                id: Self.peerDecoder,
                direction: .unidirectional,
                inbound: [([0x03], false)]
            )
        ]
        for stream in streams {
            quic.accept(stream)
        }
        return streams
    }

    /// The control stream's §6.2.1 opening: the type byte `0x00` then an empty SETTINGS frame.
    private static let controlPreamble: [UInt8] = [0x00, 0x04, 0x00]

    /// A request field section with prefix RIC=1/Base=0 whose `:authority` is a dynamic reference —
    /// blocked until ``insertAuthority`` arrives on the peer's encoder stream (RFC 9204 §4.5).
    private static let blockedFieldSection: [UInt8] = [0x02, 0x00, 0xD1, 0xD7, 0xC1, 0x80]

    /// The encoder-stream instruction inserting `:authority: dyn.example` (a static name reference).
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

    /// A server whose every read budget is short, so one advance passes all of them at once.
    private static func makeServer(
        clock: TestClock,
        handled: AsyncEventProbe<String>
    ) throws -> Server {
        let limits = HTTPLimits.default.with {
            $0.headerReadTimeout = .seconds(30)
            $0.idleTimeout = .seconds(30)
            $0.keepAliveTimeout = .seconds(30)
        }
        return HTTPServer(
            transport: try TransportFactory.make(
                TransportConfiguration(port: 0, backbone: .fake)
            ),
            responder: ClosureResponder { request, _, _ in
                handled.record(request.path)
                return ServerResponse(HTTPResponse(status: .ok), body: [])
            },
            limits: limits,
            clock: clock
        )
    }

    /// The engine of the one connection this server is serving.
    private static func engine(of server: Server) async throws -> Server.Engine {
        try await Self.settle { server.liveHTTP3ConnectionCount == 1 }
        let scope = server.activeQUICConnections.withLock(\.values.first)
        return try #require(scope).engine
    }

    /// Advances `clock` in `step`s, letting the watchdog run between each.
    private static func advance(_ clock: TestClock, by step: Duration, times: Int) async throws {
        for _ in 0 ..< times {
            clock.advance(by: step)
            try await Task.sleep(for: .milliseconds(5))
        }
    }

    /// Polls an async `condition` until it holds, failing the test if the budget runs out.
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
