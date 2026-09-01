//
//  HTTP2InboundBackpressureTests.swift
//  HTTPServerTests
//
//  The 2026-07-31 audit's finding 3 regression. The HTTP/2 reader used to yield inbound octets straight
//  into an `.unbounded` mailbox in an unconditional `while true`, while its sole consumer also did
//  protocol work and drove `connection.send`. A peer that outpaced that consumer therefore grew server
//  memory without limit — and the audit calls out flow-control-exempt traffic specifically, because it
//  is not bounded by any window.
//
//  A blocked *handler* cannot demonstrate this: HTTP/2 dispatches handlers to task-group children, so
//  the consumer keeps draining. What stalls the consumer is a peer that stops reading, which blocks
//  `connection.send` inside the flush. That is exactly the shape reproduced here, with PING — cheap to
//  send, exempt from flow control, and answered with a PONG that must be flushed.
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — HTTP/2 inbound backpressure (audit F3)")
struct HTTP2InboundBackpressureTests {
    /// The reader must stop pulling octets once the intake channel reaches its byte watermark.
    ///
    /// With the consumer stalled in `send`, an unbounded intake would swallow every staged chunk; the
    /// bounded one parks the reader, which in a real deployment stops draining the kernel receive buffer
    /// and closes the peer's TCP window. The plateau is observed by yielding until the count stops
    /// moving — the reader does no timed work, so once it stops it has parked.
    @Test("a PING flood against a stalled consumer parks the reader instead of buffering it all")
    func readerParksAtTheWatermark() async {
        let floodChunks = 400
        var staged: [[UInt8]] = [Self.clientPreface + Self.settingsFrame]
        staged += (0 ..< floodChunks).map { Self.pingFrame(UInt64($0)) }
        let connection = BlockingSendConnection(chunks: staged)

        // ~60 PINGs, far below the 400 staged.
        let limits = HTTPLimits.default.with { $0.maxQueuedInboundBytes = 1_024 }
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.get("/") { _, _, _ in .text("ok") } },
            limits: limits
        )

        let observer = Task {
            let plateau = await Self.settledHandedOutCount(connection)
            await connection.releaseSends()
            return plateau
        }
        await server.serve(connection)
        let plateau = await observer.value

        #expect(plateau > 0)  // it read *something*
        #expect(plateau < floodChunks)  // …but parked well before draining the flood
        #expect(await connection.handedOutCount() == staged.count)  // and resumed once unblocked
    }

    /// Backpressure must not cost correctness: every staged octet still reaches the engine.
    @Test("no inbound octet is lost across a watermark crossing")
    func deliversEveryOctetAcrossTheWatermark() async {
        var staged: [[UInt8]] = [Self.clientPreface + Self.settingsFrame]
        staged += (0 ..< 200).map { Self.pingFrame(UInt64($0)) }
        let connection = BlockingSendConnection(chunks: staged)
        let limits = HTTPLimits.default.with { $0.maxQueuedInboundBytes = 512 }
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.get("/") { _, _, _ in .text("ok") } },
            limits: limits
        )

        let releaser = Task {
            _ = await Self.settledHandedOutCount(connection)
            await connection.releaseSends()
        }
        await server.serve(connection)
        await releaser.value

        // One PING ACK per PING (RFC 9113 §6.7), so the engine saw all 200.
        #expect(await connection.pingAckCount() == 200)
    }

    /// Yields until the reader's pull count stops moving, then reports it.
    private static func settledHandedOutCount(_ connection: BlockingSendConnection) async -> Int {
        var last = -1
        for _ in 0 ..< 20 {
            let before = await connection.handedOutCount()
            for _ in 0 ..< 500 {
                await Task.yield()
            }
            let after = await connection.handedOutCount()
            if before == after, before == last {
                return after
            }
            last = after
        }
        return await connection.handedOutCount()
    }

    // MARK: Fixtures

    private static let clientPreface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// An empty client SETTINGS frame (RFC 9113 §6.5): length 0, type 0x04, no flags, stream 0.
    private static let settingsFrame: [UInt8] = [0, 0, 0, 0x04, 0, 0, 0, 0, 0]

    /// A PING frame (RFC 9113 §6.7): length 8, type 0x06, no flags, stream 0, 8-octet opaque data.
    private static func pingFrame(_ payload: UInt64) -> [UInt8] {
        var frame: [UInt8] = [0, 0, 8, 0x06, 0, 0, 0, 0, 0]
        for shift in stride(from: 56, through: 0, by: -8) {
            frame.append(UInt8(truncatingIfNeeded: payload >> UInt64(shift)))
        }
        return frame
    }
}
