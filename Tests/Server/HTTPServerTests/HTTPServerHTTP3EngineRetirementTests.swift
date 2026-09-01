//
//  HTTPServerHTTP3EngineRetirementTests.swift
//  HTTPServerTests
//
//  Audit REG-3 — resetting a QUIC stream on the wire tells the sans-I/O ``HTTP3Connection`` engine
//  nothing. The addendum P0.5 deadline path reset the writer and dropped the registry entry, but left
//  the engine holding the stream's parser buffer, its decoded request, its buffered body, and its slot
//  in the SETTINGS_QPACK_BLOCKED_STREAMS allowance (RFC 9204 §2.1.2) — and never charged the RFC 9114
//  §8.1 rolling reset budget for it.
//
//  So the defense added to stop a slow loris was itself slow-loris shaped: each abandoned partial
//  stream cost the peer nothing and cost the server permanent state on a long-lived connection.
//
//  Timed against an injected ``TestClock``, so the deadline fires exactly when the test advances time.
//

import HTTP3
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Synchronization
import Testing

@testable import HTTPServer

@Suite("HTTP/3 — the engine is retired with the stream (audit REG-3)")
struct HTTPServerHTTP3EngineRetirementTests {
    /// The server under test, spelled once so the engine accessor's signature stays on one line.
    private typealias Server = HTTPServer<TestClock>

    private static let partialStreams = 8

    @Test("partial streams reaped by their deadline return the engine to baseline")
    func lapsedStreamsRetireEngineState() async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let server = try Self.makeServer(clock: clock)
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        // Each stream sends a complete HEADERS and a DATA prefix, then stops: valid so far, never
        // finished. That is the shape the deadline exists for, and the shape that accumulates.
        let partial = Self.partialRequest()
        let streams = (0 ..< Self.partialStreams)
            .map { index in
                FakeQUICStream(
                    id: QUICStreamID(UInt64(index) * 4),
                    direction: .bidirectional,
                    inbound: [(partial, false)]
                )
            }
        for stream in streams {
            quic.accept(stream)
        }

        let engine = try await Self.engine(of: server)
        try await settle { await engine.census().trackedStreams == Self.partialStreams }
        let loaded = await engine.census()
        #expect(loaded.trackedStreams == Self.partialStreams)
        #expect(loaded.bufferedRequestBodyBytes > 0)  // the DATA prefix really is retained
        #expect(loaded.chargedStreamResets == 0)

        try await advance(clock, by: .seconds(31)) {
            streams.allSatisfy { !$0.resetCodes.isEmpty }
        }
        try await settle { await engine.census().trackedStreams == 0 }

        let reaped = await engine.census()
        #expect(streams.allSatisfy { !$0.resetCodes.isEmpty })
        #expect(reaped.trackedStreams == 0)  // the stream table is back to baseline
        #expect(reaped.blockedSections == 0)  // and so is the blocked-stream allowance
        #expect(reaped.bufferedRequestBodyBytes == 0)
        // Each abandoned stream is charged against the RFC 9114 §8.1 budget, so repeating it is not
        // free — that is why `resetStream` is the entry point rather than a bespoke partial cleanup.
        #expect(reaped.chargedStreamResets == Self.partialStreams)
    }

    @Test("a truncated streaming upload retires the engine along with the reset")
    func aTruncatedUploadRetiresEngineState() async throws {
        let clock = TestClock()
        let quic = FakeQUICConnection()
        let server = try Self.makeServer(clock: clock, streamingUploads: true)
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }

        // A streaming route takes the stream over at HEADERS; the peer then hangs up mid-body without
        // a FIN, so the request is refused with H3_REQUEST_INCOMPLETE (RFC 9114 §8.1).
        let upload = FakeQUICStream(
            id: QUICStreamID(0),
            direction: .bidirectional,
            inbound: [(Self.partialRequest(method: "POST", path: "/upload"), false)]
        )
        quic.accept(upload)

        let engine = try await Self.engine(of: server)
        try await settle { await engine.census().trackedStreams == 1 }
        upload.finishInbound()  // peer EOF mid-upload

        try await settle { await engine.census().trackedStreams == 0 }
        #expect(upload.resetCodes == [HTTP3ErrorCode.h3RequestIncomplete.rawValue])
        #expect(await engine.census().chargedStreamResets == 1)
    }

    // MARK: - Fixtures

    /// The engine of the one connection this server is serving.
    private static func engine(of server: Server) async throws -> Server.Engine {
        try await settle { server.liveHTTP3ConnectionCount == 1 }
        let handle = server.activeQUICConnections.withLock(\.values.first)
        return try #require(handle).engine
    }

    /// A server on `clock` with a 30 s header budget, so one advance past it reaps every partial stream.
    private static func makeServer(
        clock: TestClock,
        streamingUploads: Bool = false
    ) throws -> Server {
        let limits = HTTPLimits.default.with {
            $0.headerReadTimeout = .seconds(30)
            $0.idleTimeout = .seconds(120)
            $0.keepAliveTimeout = .seconds(30)
        }
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

    /// A complete HEADERS frame followed by a DATA prefix and no FIN (RFC 9114 §4.1).
    private static func partialRequest(method: String = "GET", path: String = "/") -> [UInt8] {
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
        let body = [UInt8](repeating: 0x61, count: 32)
        QUICVarint.encode(0x00, into: &out)
        QUICVarint.encode(UInt64(body.count), into: &out)
        out.append(contentsOf: body)
        return out
    }
}
