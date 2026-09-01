//
//  HTTPServerHTTP3TruncationTests.swift
//  HTTPServerTests
//
//  RFC 9114 §4.1 / §8.1 — a streaming HTTP/3 request whose body never reached a valid end must not be
//  answered as if it had. QUIC's FIN is the positive end-of-body signal, and the engine converts it
//  into a `requestEnd` event; an EOF, a reset, or a receive failure produces none.
//
//  Audit addendum P0.5 (second correctness edge): the driver finished the handoff, awaited the
//  handler, and sent its response regardless — a truncated upload delivered to the handler as a
//  complete one, and answered `200`. These tests pin the stream being reset with
//  H3_REQUEST_INCOMPLETE instead, with nothing written back.
//

import HTTP3
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Testing

@testable import HTTPServer

@Suite("HTTP/3 driver — a truncated request body is not a complete one (addendum P0.5)")
struct HTTPServerHTTP3TruncationTests {
    private static let requestStream = QUICStreamID(0)

    @Test("a streaming request body cut off before FIN resets the stream and sends no response")
    func truncatedStreamingBodyIsRejected() async throws {
        let entered = AsyncEventProbe<String>()
        let server = try Self.makeStreamingServer(entered)
        let quic = FakeQUICConnection()
        let consumed = AsyncEventProbe<QUICStreamID>()

        // HEADERS + a partial DATA frame, with no FIN: the peer then simply stops (EOF).
        let request = FakeQUICStream(
            id: Self.requestStream,
            direction: .bidirectional,
            inbound: [(Self.headersFrame() + Self.dataFrame(Array("part".utf8)), false)],
            consumed: consumed
        )

        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }
        quic.accept(request)
        _ = try await entered.wait(forAtLeast: 1)  // the handler is running on the partial body
        request.finishInbound()  // EOF without FIN — the body is truncated

        try await settle { !request.resetCodes.isEmpty }
        #expect(request.resetCodes == [HTTP3ErrorCode.h3RequestIncomplete.rawValue])
        #expect(request.sendCount == 0)  // no response head, no body, no FIN
    }

    @Test("a streaming request body that reaches FIN is still answered normally")
    func completeStreamingBodyIsAnswered() async throws {
        let entered = AsyncEventProbe<String>()
        let server = try Self.makeStreamingServer(entered)
        let quic = FakeQUICConnection()

        let request = FakeQUICStream(
            id: Self.requestStream,
            direction: .bidirectional,
            inbound: [(Self.headersFrame() + Self.dataFrame(Array("whole".utf8)), true)]
        )

        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }
        quic.accept(request)

        try await settle { request.sendCount > 0 }
        #expect(request.resetCodes.isEmpty)
        #expect(request.sendCount > 0)
    }

    // MARK: - Fixtures

    /// A server whose `/upload` route streams its request body and echoes the octet count.
    private static func makeStreamingServer(
        _ entered: AsyncEventProbe<String>
    ) throws -> HTTPServer<ContinuousClock> {
        let router = Router {
            Route.post("/upload") { _, body, _ in
                entered.record("upload")
                return .text("bytes=\(await body.collect().count)")
            }
            .streamingBody()
        }
        return HTTPServer(
            transport: try TransportFactory.make(
                TransportConfiguration(port: 0, backbone: .fake)
            ),
            responder: router
        )
    }

    /// A HEADERS frame for `POST /upload` (RFC 9114 §7.2.2), QPACK-encoded statically.
    private static func headersFrame() -> [UInt8] {
        let section = QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: "POST"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "example.com"),
                HeaderField(name: ":path", value: "/upload")
            ])
        return frame(0x01, section)
    }

    /// A DATA frame (RFC 9114 §7.2.1) carrying `payload`.
    private static func dataFrame(_ payload: [UInt8]) -> [UInt8] {
        frame(0x00, payload)
    }

    private static func frame(_ type: UInt64, _ payload: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        QUICVarint.encode(type, into: &out)
        QUICVarint.encode(UInt64(payload.count), into: &out)
        out.append(contentsOf: payload)
        return out
    }
}
