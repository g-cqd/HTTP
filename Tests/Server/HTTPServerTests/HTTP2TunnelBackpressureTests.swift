//
//  HTTP2TunnelBackpressureTests.swift
//  HTTPServerTests
//
//  The 2026-07-31 audit's regression for finding 2: WebSocket-over-HTTP/2 tunnel intake is
//  consumption-gated (RFC 8441 §5, RFC 9113 §6.9).
//
//  Tunnel DATA is opaque. The engine's own comment said so approvingly — "never buffered as a request
//  body or bounded by the body limit" — which meant it was bounded by *nothing at all*: the window was
//  replenished on receipt and the bytes went into an `.unbounded` `AsyncStream`, so a perfectly
//  conforming peer talking to a blocked handler could grow the server's memory without limit. This is
//  the one gated path where the CONNECTION window, not the per-stream one, is the interesting bound,
//  because a peer can open many tunnels.
//
//  Everything here is observed from the wire: what the server has credited back with WINDOW_UPDATE is
//  exactly what its handlers have processed, so offered-minus-credited is the live memory held.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing
import WebSocket

@testable import HTTPServer

// `.serialized` for the same reason as the request-body suite: a polling peer against a full serve loop
// starves its siblings when several run at once.
@Suite("Audit F2 — WebSocket-over-HTTP/2 tunnel backpressure", .serialized)
struct HTTP2TunnelBackpressureTests {
    private static let streamWindow = H2ServerWire.maxFrame
    private static let connectionWindow = 4 * H2ServerWire.maxFrame

    private static var limits: HTTPLimits {
        HTTPLimits(
            streamReceiveWindow: streamWindow,
            connectionReceiveWindow: connectionWindow
        )
    }

    private static func settle(rounds: Int = 1) async {
        for _ in 0 ..< rounds {
            try? await Task.sleep(for: .milliseconds(1))
        }
    }

    /// A WebSocket binary frame with a `count`-octet masked payload — what a real client sends.
    private static func maskedBinary(count: Int) -> [UInt8] {
        let payload = [UInt8](repeating: 0x5A, count: count)
        let key: [UInt8] = [0x11, 0x22, 0x33, 0x44]
        var frame: [UInt8] = [0x82]  // FIN + binary
        if count < 126 {
            frame.append(0x80 | UInt8(count))
        }
        else {
            frame.append(0x80 | 126)
            frame += [UInt8(count >> 8 & 0xFF), UInt8(count & 0xFF)]
        }
        frame += key
        for (index, byte) in payload.enumerated() { frame.append(byte ^ key[index & 0x3]) }
        return frame
    }

    @Test(
        "a blocked tunnel handler stalls its peer at the stream window",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
    func blockedHandlerStallsThePeer() async throws {
        let blocked = AsyncGate()
        let handler = ClosureWebSocketHandler { _ in
            try? await blocked.waitUntilOpen()
            return []
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: handler) },
            limits: Self.limits
        )
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.extendedConnect(streamID: 1, path: "/chat")
        )
        // Offer exactly one window of tunnel DATA, then wait for the handler to be provably parked on
        // the first frame it was given.
        await connection.feed(
            H2ServerWire.data(streamID: 1, payload: Self.maskedBinary(count: 64))
        )
        try await blocked.waitForWaiters(atLeast: 1)
        await connection.feed(
            H2ServerWire.dataFrames(streamID: 1, total: Self.streamWindow - 70)
        )
        await Self.settle(rounds: 50)

        // Nothing has been credited: the handler processed nothing, so the peer gets no window back.
        // Under arrival-replenish every one of these octets was credited the instant it landed, and the
        // peer could have kept going with no bound whatsoever.
        #expect(H2ServerWire.creditedBytes(onStream: 1, in: await connection.sentBytes()) == 0)

        blocked.open()
        await connection.finishInbound()
        await serving.value
    }

    @Test(
        "memory stays flat across 64 MiB of offered tunnel DATA against a blocked handler",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 2)))
    func memoryIsStableAcrossALargeOffer() async {
        let blocked = AsyncGate()
        let handler = ClosureWebSocketHandler { _ in
            try? await blocked.waitUntilOpen()
            return []
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: handler) },
            limits: Self.limits
        )
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.extendedConnect(streamID: 1, path: "/chat")
        )
        // A conforming peer offering 64 MiB: it may only ever have one window outstanding, so it stalls
        // almost immediately and the 64 MiB is never actually admitted. The measurable claim is that
        // total admitted octets stay at the window, not that the peer stops trying.
        let target = 64 << 20
        var offered = 0
        var rounds = 0
        while offered < target, rounds < 500, !Task.isCancelled {
            rounds += 1
            let sent = await connection.sentBytes()
            let credited = H2ServerWire.creditedBytes(onStream: 1, in: sent)
            guard offered - credited < Self.streamWindow else {
                break  // stalled: the peer has a full window outstanding and no credit is coming
            }
            offered += H2ServerWire.maxFrame
            await connection.feed(
                H2ServerWire.dataFrames(streamID: 1, total: H2ServerWire.maxFrame)
            )
            await Self.settle()
        }
        // Admitted at most one window, out of 64 MiB offered. That IS the memory bound: the octets a
        // blocked handler is holding are exactly the ones the peer was allowed to send.
        #expect(offered <= Self.streamWindow + H2ServerWire.maxFrame)
        #expect(offered < target)  // the peer really was stalled, not merely finished

        blocked.open()
        await connection.finishInbound()
        await serving.value
    }

    @Test(
        "a sibling tunnel with a live handler keeps exchanging frames across a blocked one",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
    func siblingTunnelKeepsRunning() async throws {
        let blocked = AsyncGate()
        let stuck = ClosureWebSocketHandler { _ in
            try? await blocked.waitUntilOpen()
            return []
        }
        let echo = ClosureWebSocketHandler { event in
            guard case .message(let opcode, let payload) = event, opcode == .binary else {
                return []
            }
            return [.sendBinary(payload)]
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router {
                Route.webSocket("/stuck", handler: stuck)
                Route.webSocket("/echo", handler: echo)
            },
            limits: Self.limits
        )
        let serving = Task { await server.serve(connection) }

        await connection.feed(
            H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.extendedConnect(streamID: 1, path: "/stuck")
                + H2ServerWire.extendedConnect(streamID: 3, path: "/echo")
        )
        // Wedge stream 1's handler on its first frame, so it holds its whole window indefinitely.
        await connection.feed(
            H2ServerWire.data(streamID: 1, payload: Self.maskedBinary(count: 64))
        )
        try await blocked.waitForWaiters(atLeast: 1)

        // Stream 3 must keep working: head-of-line blocking between tunnels is exactly what the
        // per-tunnel pump task and per-stream gate exist to prevent.
        for round in 0 ..< 4 {
            await connection.feed(
                H2ServerWire.data(streamID: 3, payload: Self.maskedBinary(count: 32))
            )
            while H2ServerWire.body(onStream: 3, in: await connection.sentBytes()).count
                < 34 * (round + 1), !Task.isCancelled
            {
                await Self.settle()
            }
        }
        let echoed = H2ServerWire.body(onStream: 3, in: await connection.sentBytes())
        #expect(echoed.count >= 34 * 4)  // four unmasked 32-octet binary frames came back
        // And the wedged tunnel has still answered nothing on its own stream beyond the 200.
        #expect(H2ServerWire.creditedBytes(onStream: 1, in: await connection.sentBytes()) == 0)

        blocked.open()
        await connection.finishInbound()
        await serving.value
    }
}
