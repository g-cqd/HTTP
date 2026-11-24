//
//  StreamingOptimizationTests.swift
//  HTTPServerTests
//
//  Deterministic regression tests for g-cqd/HTTP issues #2, #3, and #4:
//    • #2 — `H1StreamWriter.write` dispatches chunked frames via 3-part scatter-gather
//           `send(_:_:_:)` with stack-formatted hex size lines (zero payload coalescing copy).
//    • #3 — `posixKqueue` shutdown + cancellation while a streaming connection is active never
//           triggers re-entrant `runSynchronously` / `os_unfair_lock` abort.
//    • #4 — `ResponseStream(producerIdleTimeout:)` allows quiet event-driven producers past the
//           global `HTTPLimits.idleTimeout` without raising the server-wide limit.
//

import Foundation
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — Zero-copy streaming, producerIdleTimeout & kqueue teardown (#2, #3, #4)")
struct StreamingOptimizationTests {
    @Test("H1StreamWriter uses 3-part scatter-gather send(_:_:_:) without payload coalescing (#2)")
    func chunkedStreamUsesScatterGather() async {
        let conn = SpyScatterConnection(
            id: TransportConnectionID(1),
            inbound: Array("GET /live HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        let payload = [UInt8](repeating: 0xAB, count: 4_096)
        let responder = ClosureResponder { _, _, _ in
            .streaming(contentType: "application/octet-stream") { writer in
                try await writer.write([UInt8](repeating: 0x11, count: 0x1A))
                try await writer.write(payload)
            }
        }
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(conn)

        let triplets = conn.recordedTriplets()
        #expect(triplets.count == 2)
        #expect(triplets[0].0 == Array("1a\r\n".utf8))
        #expect(triplets[0].1.count == 0x1A)
        #expect(triplets[0].2 == [0x0D, 0x0A])
        #expect(triplets[1].0 == Array("1000\r\n".utf8))
        #expect(triplets[1].1 == payload)
        #expect(triplets[1].2 == [0x0D, 0x0A])
    }

    @Test(
        "ResponseStream.producerIdleTimeout keeps quiet push stream alive past short global idleTimeout (#4)",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1))
    )
    func producerIdleTimeoutOverridesGlobalIdleTimeout() async throws {
        let clock = TestClock()
        let limits = HTTPLimits(
            headerReadTimeout: .seconds(60),
            idleTimeout: .seconds(1),
            keepAliveTimeout: .seconds(60)
        )
        let producerGate = AsyncGate()
        let firstChunkWritten = AsyncEventProbe<Int>()
        let responder = ClosureResponder { _, _, _ in
            let stream = ResponseStream(producerIdleTimeout: .seconds(30)) { writer in
                try await writer.write(Array("first".utf8))
                firstChunkWritten.record(1)
                // Stay quiet well past the 1s global idleTimeout, but under 30s producerIdleTimeout.
                try await producerGate.waitUntilOpen()
                try await writer.write(Array("second".utf8))
            }
            return ServerResponse(HTTPResponse(status: .ok), stream: stream)
        }
        let conn = SpyScatterConnection(
            id: TransportConnectionID(1),
            inbound: Array("GET /push HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: responder,
            limits: limits,
            clock: clock
        )

        let serveTask: Task<Void, Never> = Task { await server.serve(conn) }
        _ = try await firstChunkWritten.wait(forAtLeast: 1)
        try await producerGate.waitForWaiters(atLeast: 1)

        // Wait until the idle-watchdog sleeper is registered on TestClock, then advance 5 seconds
        // (5x the 1s global idleTimeout, still well under the 30s producerIdleTimeout).
        try await clock.waitForSleepers(atLeast: 1)
        clock.advance(by: .seconds(5))
        #expect(!conn.isClosed)

        producerGate.open()
        await serveTask.value

        let wire = String(decoding: conn.allSentBytes(), as: Unicode.UTF8.self)
        #expect(wire.contains("5\r\nfirst\r\n"))
        #expect(wire.contains("6\r\nsecond\r\n"))
        #expect(wire.hasSuffix("0\r\n\r\n"))
    }

    #if os(macOS)
        @Test(
            "posixKqueue shutdown + task cancellation while a ResponseStream is active does not crash (#3)",
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1))
        )
        func posixKqueueShutdownWhileStreamingDoesNotCrash() async throws {
            for _ in 0 ..< 5 {
                let firstChunk = AsyncEventProbe<Int>()
                let responder = ClosureResponder { _, _, _ in
                    let stream = ResponseStream(producerIdleTimeout: .seconds(60)) { writer in
                        try await writer.write(Array("hello".utf8))
                        firstChunk.record(1)
                        while !Task.isCancelled {
                            try await Task.sleep(for: .milliseconds(20))
                            try await writer.write(Array("tick".utf8))
                        }
                    }
                    return ServerResponse(HTTPResponse(status: .ok), stream: stream)
                }
                let config = TransportConfiguration(
                    host: "127.0.0.1",
                    port: 0,
                    backbone: .posixKqueue,
                    eventLoopCount: 1
                )
                let transport = try TransportFactory.make(config)
                let server = HTTPServer(transport: transport, responder: responder)
                let runTask: Task<Void, Never> = Task { try? await server.run() }

                var port: UInt16 = 0
                for _ in 0 ..< 100 {
                    let bound = transport.boundPort
                    if bound != 0 {
                        port = bound
                        break
                    }
                    try await Task.sleep(for: .milliseconds(5))
                }
                #expect(port != 0)

                let clientTask = Task {
                    let url = try #require(URL(string: "http://127.0.0.1:\(port)/live"))
                    let session = URLSession(configuration: .ephemeral)
                    defer { session.invalidateAndCancel() }
                    if let (bytes, _) = try? await session.bytes(from: url) {
                        do {
                            for try await _ in bytes {
                                // Drain streaming chunks until server shutdown cancels the stream.
                            }
                        }
                        catch {
                            // Expected when shutdown closes the peer socket mid-stream.
                        }
                    }
                }

                _ = try await firstChunk.wait(forAtLeast: 1)
                await server.shutdown(within: .milliseconds(100))
                runTask.cancel()
                await runTask.value
                clientTask.cancel()
            }
        }
    #endif
}
