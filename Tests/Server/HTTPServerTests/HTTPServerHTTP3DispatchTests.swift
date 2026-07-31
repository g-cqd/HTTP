//
//  HTTPServerHTTP3DispatchTests.swift
//  HTTPServerTests
//
//  RFC 9204 §2.1.2 through the *live* HTTP/3 server driver: a request whose QPACK field section
//  references a dynamic-table entry that has not arrived is blocked, and the engine surfaces it from
//  the **encoder stream's** `receive` — a different stream than the one the request came in on
//  (`HTTP3DynamicQpackTests.blockedRequestUnblocksOnInsert` proves that at the sans-I/O layer).
//
//  Audit addendum P0.3: the driver used to answer such a request on whichever stream's task made the
//  engine call, and `applyHTTP3` then dropped every action whose id did not match that task's stream —
//  so the response was written nowhere. These tests pin the routing: the handler runs exactly once and
//  the response is written only on the request stream.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Testing

@testable import HTTPServer

@Suite("HTTP/3 driver — engine output is routed by stream id (addendum P0.3)")
struct HTTPServerHTTP3DispatchTests {
    private static let requestStream = QUICStreamID(0)
    private static let encoderStream = QUICStreamID(6)

    @Test("a QPACK-blocked request is answered on its own stream, not the encoder stream")
    func blockedRequestIsAnsweredOnItsOwnStream() async throws {
        let handled = AsyncEventProbe<String>()
        let server = try Self.makeServer(handled)
        let quic = FakeQUICConnection()
        let consumed = AsyncEventProbe<QUICStreamID>()

        // The request indexes a dynamic `:authority` (RIC=1) that has not been inserted yet, with FIN:
        // the engine buffers it (RFC 9204 §2.1.2) and surfaces nothing on this stream's own receive.
        let request = FakeQUICStream(
            id: Self.requestStream,
            direction: .bidirectional,
            inbound: [(Self.headersFrame(Self.blockedFieldSection), true)],
            consumed: consumed
        )
        let encoder = FakeQUICStream(
            id: Self.encoderStream,
            direction: .unidirectional,
            consumed: consumed
        )

        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }
        quic.accept(request)
        quic.accept(encoder)
        // Order the two streams without sleeping: the insert is delivered only after the blocked
        // request's bytes have reached the engine.
        _ = try await consumed.wait(forAtLeast: 1)
        encoder.deliver([0x02] + Self.insertAuthority, fin: false)

        _ = try await handled.wait(forAtLeast: 1)
        try await Self.settle { request.sendCount > 0 }

        #expect(handled.count == 1)  // the handler ran exactly once, for the request stream
        #expect(encoder.sendCount == 0)  // and nothing was written on the encoder stream
        let (status, body) = try Self.decodeResponse(request.sentBytes)
        #expect(status == "200")
        #expect(body == Array("dyn.example".utf8))
    }

    @Test("one insert unblocks two request streams, each answered on its own stream")
    func twoBlockedRequestsAreAnsweredOnTheirOwnStreams() async throws {
        let handled = AsyncEventProbe<String>()
        let server = try Self.makeServer(handled)
        let quic = FakeQUICConnection()
        let consumed = AsyncEventProbe<QUICStreamID>()

        let first = FakeQUICStream(
            id: QUICStreamID(0),
            direction: .bidirectional,
            inbound: [(Self.headersFrame(Self.blockedFieldSection), true)],
            consumed: consumed
        )
        let second = FakeQUICStream(
            id: QUICStreamID(4),
            direction: .bidirectional,
            inbound: [(Self.headersFrame(Self.blockedFieldSection), true)],
            consumed: consumed
        )
        let encoder = FakeQUICStream(
            id: Self.encoderStream,
            direction: .unidirectional,
            consumed: consumed
        )

        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }
        quic.accept(first)
        quic.accept(second)
        quic.accept(encoder)
        // Both requests reached the engine and blocked before the insert is delivered.
        _ = try await consumed.wait(forAtLeast: 2)
        encoder.deliver([0x02] + Self.insertAuthority, fin: false)

        _ = try await handled.wait(forAtLeast: 2)
        try await Self.settle { first.sendCount > 0 && second.sendCount > 0 }

        #expect(handled.count == 2)  // exactly once per stream, never twice for either
        #expect(encoder.sendCount == 0)
        #expect(try Self.decodeResponse(first.sentBytes).0 == "200")
        #expect(try Self.decodeResponse(second.sentBytes).0 == "200")
    }

    @Test("a QPACK-unblocked stream is woken with no further bytes on its own stream")
    func blockedStreamIsWokenWithoutFurtherInboundBytes() async throws {
        let handled = AsyncEventProbe<String>()
        let server = try Self.makeStreamingServer(handled)
        let quic = FakeQUICConnection()
        let consumed = AsyncEventProbe<QUICStreamID>()

        // The same blocked field section as above, but **without FIN** — the case audit REG-2 found.
        // A streaming route (Phase 1.4) surfaces `requestHead` as soon as the section decodes, so the
        // engine really does route an event to this stream while its task is parked on `receive()`.
        // With no FIN the peer sends nothing more, so the *only* thing that can run the handler is the
        // deposit waking the owner; before REG-2 the event sat in the mailbox until the read deadline.
        let request = FakeQUICStream(
            id: Self.requestStream,
            direction: .bidirectional,
            inbound: [(Self.headersFrame(Self.blockedFieldSection), false)],
            consumed: consumed
        )
        let encoder = FakeQUICStream(
            id: Self.encoderStream,
            direction: .unidirectional,
            consumed: consumed
        )

        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }
        quic.accept(request)
        quic.accept(encoder)
        _ = try await consumed.wait(forAtLeast: 1)
        encoder.deliver([0x02] + Self.insertAuthority, fin: false)

        // No further bytes are delivered on the request stream before this boundary.
        _ = try await handled.wait(forAtLeast: 1)
        #expect(handled.count == 1)
        #expect(request.resetCodes.isEmpty)  // it was woken, not reaped by its read deadline

        // And the response lands on the request stream once the body ends.
        request.deliver([], fin: true)
        try await Self.settle { request.sendCount > 0 }
        #expect(try Self.decodeResponse(request.sentBytes).0 == "200")
        #expect(encoder.sendCount == 0)
    }

    // MARK: - Fixtures

    /// A responder echoing the request authority, recording each invocation on `probe`.
    private static func makeServer(
        _ probe: AsyncEventProbe<String>
    ) throws -> HTTPServer<ContinuousClock> {
        let responder = ClosureResponder { request, _, _ in
            probe.record(request.path)
            return ServerResponse(
                HTTPResponse(status: .ok), body: Array((request.authority ?? "").utf8)
            )
        }
        return HTTPServer(
            transport: try TransportFactory.make(
                TransportConfiguration(port: 0, backbone: .fake)
            ),
            responder: responder
        )
    }

    /// A server whose one route consumes its body as a stream (Phase 1.4), so the engine surfaces a
    /// `requestHead` for it as soon as the QPACK section decodes — without waiting for FIN.
    private static func makeStreamingServer(
        _ probe: AsyncEventProbe<String>
    ) throws -> HTTPServer<ContinuousClock> {
        let router = Router {
            Route.get("/") { request, _, _ in
                probe.record(request.path)
                return .text("ok")
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

    /// A request field section with prefix RIC=1/Base=0: static `:method`/`:scheme`/`:path` plus a
    /// dynamic indexed `:authority` (RFC 9204 §4.5) — blocked until the insert below arrives.
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

    /// Decodes a server response off the wire: the `:status` and the concatenated DATA payloads.
    private static func decodeResponse(_ bytes: [UInt8]) throws -> (String?, [UInt8]) {
        var status: String?
        var body: [UInt8] = []
        var index = 0
        while index < bytes.count {
            let rest = Array(bytes[index...])
            guard let frame = Self.nextFrame(rest) else {
                break
            }
            index += frame.consumed
            switch frame.type {
                case 0x01:
                    let fields = try frame.payload.withUnsafeBytes {
                        try QPACKDecoder().decode($0.bytes)
                    }
                    for field in fields where field.name == ":status" { status = field.value }
                case 0x00:
                    body.append(contentsOf: frame.payload)
                default:
                    break
            }
        }
        return (status, body)
    }

    /// One HTTP/3 frame (Type, Length, payload) off the front of `bytes`.
    private static func nextFrame(
        _ bytes: [UInt8]
    ) -> (type: UInt64, payload: [UInt8], consumed: Int)? {
        bytes.withUnsafeBytes { raw -> (type: UInt64, payload: [UInt8], consumed: Int)? in
            var reader = ByteReader(raw)
            guard let type = QUICVarint.decode(&reader),
                let length = QUICVarint.decode(&reader),
                reader.position + Int(length) <= bytes.count
            else {
                return nil
            }
            let start = reader.position
            return (type, Array(bytes[start ..< (start + Int(length))]), start + Int(length))
        }
    }

    /// Polls `condition` until it holds, failing the test if the budget runs out.
    ///
    /// The budget exhausting is a *failure*, not a quiet return. Falling out of the loop with the
    /// condition still false let the test carry on and either pass vacuously or fail later at a
    /// confusing assertion — which is how a genuinely unmet condition could read as a green run.
    private static func settle(until condition: @Sendable () -> Bool) async throws {
        for _ in 0 ..< 200 where !condition() {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(condition(), "settle budget exhausted with the condition still false")
    }
}
