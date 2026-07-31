//
//  HTTPServerHTTP3DeadlineTests.swift
//  HTTPServerTests
//
//  Audit addendum P0.5 — HTTP/3 request streams had no read deadlines at all. A peer could open
//  streams up to `maxConcurrentStreams`, send one octet on each, and hold every one of them (and the
//  connection's admission slot) open forever: the Slowloris the HTTP/1.1 reader has always been
//  defended against (RFC 9112 §9.3), arriving over RFC 9114 §4.1 instead.
//
//  Timed against an injected ``TestClock``, so these run with zero real-time waiting and the deadline
//  fires exactly when the test advances the clock past it.
//

import HTTP3
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Testing

@testable import HTTPServer

@Suite("HTTP/3 — per-stream read deadlines (addendum P0.5)")
struct HTTPServerHTTP3DeadlineTests {
    @Test("a stream that opens and never sends HEADERS is reset as H3_REQUEST_REJECTED")
    func headerDeadlineResetsASilentStream() async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let server = try Self.makeServer(clock: clock)
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        let silent = FakeQUICStream(id: QUICStreamID(0), direction: .bidirectional)
        quic.accept(silent)
        // Advancing past the header budget is what fires the deadline — nothing waits in real time.
        try await Self.advance(clock, by: .seconds(31)) { !silent.resetCodes.isEmpty }

        #expect(silent.resetCodes == [HTTP3ErrorCode.h3RequestRejected.rawValue])
        #expect(silent.sendCount == 0)
    }

    @Test("an upload that stalls mid-body is reset as H3_REQUEST_INCOMPLETE")
    func bodyDeadlineResetsAStalledUpload() async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let server = try Self.makeServer(clock: clock, streamingUploads: true)
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        // A streaming route surfaces its head as soon as HEADERS decode, so the *body* budget applies
        // from there on — and the peer is told the request was incomplete, not that it was never
        // processed, because the head did reach the responder.
        let stalled = FakeQUICStream(
            id: QUICStreamID(0),
            direction: .bidirectional,
            inbound: [(Self.headersFrame(method: "POST", path: "/upload"), false)]
        )
        quic.accept(stalled)
        try await Self.advance(clock, by: .seconds(121)) { !stalled.resetCodes.isEmpty }

        #expect(!stalled.resetCodes.isEmpty)
        #expect(
            stalled.resetCodes.allSatisfy { $0 == HTTP3ErrorCode.h3RequestIncomplete.rawValue }
        )
        #expect(stalled.sendCount == 0)  // no response for a body that never completed
    }

    @Test("a complete request beats its deadline and is answered")
    func aPromptRequestIsNotReset() async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let server = try Self.makeServer(clock: clock)
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        let prompt = FakeQUICStream(
            id: QUICStreamID(0),
            direction: .bidirectional,
            inbound: [(Self.headersFrame(), true)]
        )
        quic.accept(prompt)

        try await Self.settle { prompt.sendCount > 0 }
        #expect(prompt.resetCodes.isEmpty)
        #expect(prompt.sendCount > 0)
    }

    // MARK: - Fixtures

    /// A server on `clock` with a 30 s header budget and a 120 s idle budget, so the two phases are
    /// distinguishable by how far the test advances time.
    private static func makeServer(
        clock: TestClock,
        streamingUploads: Bool = false
    ) throws -> HTTPServer<TestClock> {
        var limits = HTTPLimits.default
        limits.headerReadTimeout = .seconds(30)
        limits.idleTimeout = .seconds(120)
        limits.keepAliveTimeout = .seconds(30)
        let responder: any HTTPResponder =
            streamingUploads
            ? Router {
                Route.post("/upload") { _, body, _ in .text("bytes=\(await body.collect().count)") }
                    .streamingBody()
            }
            : ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok), body: []) }
        return HTTPServer(
            transport: try TransportFactory.make(
                TransportConfiguration(port: 0, backbone: .fake)
            ),
            responder: responder,
            limits: limits,
            clock: clock
        )
    }

    /// A HEADERS frame (RFC 9114 §7.2.2), QPACK-encoded statically.
    private static func headersFrame(method: String = "GET", path: String = "/") -> [UInt8] {
        let section = QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: method),
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

    /// Advances `clock` by `step` until `condition` holds, so the test never has to guess whether the
    /// serve tasks have parked on their deadline yet.
    private static func advance(
        _ clock: TestClock,
        by step: Duration,
        until condition: @Sendable () -> Bool
    ) async throws {
        for _ in 0 ..< 200 where !condition() {
            clock.advance(by: step)
            try await Task.sleep(for: .milliseconds(5))
        }
    }

    /// Polls `condition` on the cooperative pool until it holds or the budget runs out.
    private static func settle(until condition: @Sendable () -> Bool) async throws {
        for _ in 0 ..< 200 where !condition() {
            try await Task.sleep(for: .milliseconds(5))
        }
    }
}
