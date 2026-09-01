//
//  ConnectionReceiveResidencyTests.swift
//  HTTPTransportTests
//
//  ADD-P2, on a LIVE connection rather than the policy in isolation: a `POSIXKqueueConnection` over a
//  real socket pair, read through the same `receive(into:maxLength: 16_384)` the HTTP/1 request reader
//  uses, must hold `ReceiveScratch.floorWindow` octets after an ordinary request — not the 16 KiB it
//  used to size to on the first read and then keep for the connection's life.
//
//  The oracle is `receiveScratchBytes` — the octets the connection's scratch actually holds — NOT
//  allocation counting: `mallocDelta` cannot see the SIZE of an allocation, and these bodies are
//  `async` besides, which the counting hooks do not support. `ReceiveScratchTests` carries the
//  allocation-octet evidence, on the synchronous policy.
//
//  The teardown cases exist because the alternative design considered here — an owned buffer pool —
//  would have had to account for a buffer handed out on read and returned on close or cancel, and that
//  accounting is exactly what a pool gets wrong. The chosen policy has no such accounting: the scratch
//  is owned by the connection and dies with it. These pin that there is nothing to return twice and
//  nothing to leak, so the absence of the accounting is load-bearing rather than an omission.
//
//  Standards: `read(2)`, `socketpair(2)`, `shutdown(2)`, `close(2)` per POSIX.1-2017 (IEEE Std
//  1003.1-2017).
//

#if canImport(Darwin)

    import Darwin
    import Testing

    @testable import HTTPTransport

    @Suite("Receive residency on a live connection (ADD-P2)")
    struct ConnectionReceiveResidencyTests {
        /// The ceiling `HTTPServer+RequestReader` passes on every HTTP/1 read.
        private static let serverCeiling = 16_384

        /// A minimal but realistic HTTP/1.1 request head — the read this finding is about.
        private static let requestHead = Array(
            "GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: probe/1\r\n\r\n".utf8
        )

        /// A socket pair, the loop watching one end, and the connection wrapping it.
        ///
        /// Both ends get a socket buffer comfortably larger than the server ceiling so a test can write
        /// a whole payload before reading any of it without the write blocking on itself.
        private final class Fixture {
            let loop: KqueueEventLoop
            let connection: POSIXKqueueConnection
            /// The peer end — what a client would write into.
            let peer: Int32

            init() throws {
                var pair: [Int32] = [-1, -1]
                #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
                // Non-blocking on the connection's end: its read core parks on `EAGAIN` rather than
                // blocking the loop thread, which is the shape under test.
                _ = fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL, 0) | O_NONBLOCK)
                Self.widenBuffers(pair[0])
                Self.widenBuffers(pair[1])
                let loop = try KqueueEventLoop()
                loop.start()
                self.loop = loop
                peer = pair[1]
                connection = POSIXKqueueConnection(
                    id: TransportConnectionID(1),
                    descriptor: pair[0],
                    peer: TransportAddress(host: "127.0.0.1", port: 0),
                    eventLoop: loop
                )
            }

            /// Writes `bytes` from the peer end, as a client would.
            func send(_ bytes: [UInt8]) {
                var offset = 0
                bytes.withUnsafeBytes { raw in
                    while offset < raw.count {
                        let written = Darwin.write(
                            peer,
                            raw.baseAddress?.advanced(by: offset),
                            raw.count - offset
                        )
                        guard written > 0 else {
                            return
                        }
                        offset += written
                    }
                }
                #expect(offset == bytes.count)
            }

            /// Half-closes the peer's write side so the connection observes a clean end of stream.
            func finish() {
                #expect(shutdown(peer, SHUT_WR) == 0)
            }

            private static func widenBuffers(_ descriptor: Int32) {
                var size = Int32(1 << 18)
                let width = socklen_t(MemoryLayout<Int32>.size)
                _ = setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &size, width)
                _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &size, width)
            }

            deinit {
                connection.cancel()  // idempotent; closes the connection's end through the loop
                close(peer)
                loop.stop()
            }
        }

        /// Reads until `expected` octets have arrived or the stream ends, as the request reader does.
        private static func drain(
            _ fixture: Fixture,
            into buffer: inout [UInt8],
            expected: Int
        ) async throws {
            while buffer.count < expected {
                let count = try await fixture.connection.receive(
                    into: &buffer,
                    maxLength: serverCeiling
                )
                guard count > 0 else {
                    return
                }
            }
        }

        // MARK: - The finding

        @Test("an ordinary request leaves the floor resident, not the server's 16 KiB ceiling")
        func anOrdinaryRequestHoldsOnlyTheFloor() async throws {
            let fixture = try Fixture()
            #expect(fixture.connection.receiveScratchBytes == 0, "nothing is held before a read")
            fixture.send(Self.requestHead)

            var buffer: [UInt8] = []
            try await Self.drain(fixture, into: &buffer, expected: Self.requestHead.count)

            #expect(buffer == Self.requestHead)
            // BEFORE this change the same read left 16,384 octets resident for the connection's life.
            #expect(fixture.connection.receiveScratchBytes == ReceiveScratch.floorWindow)
        }

        @Test("a keep-alive connection serving many small requests never grows")
        func aKeepAliveConnectionNeverGrows() async throws {
            let fixture = try Fixture()
            for _ in 0 ..< 16 {
                fixture.send(Self.requestHead)
                var buffer: [UInt8] = []
                try await Self.drain(fixture, into: &buffer, expected: Self.requestHead.count)
                #expect(buffer == Self.requestHead)
            }
            #expect(fixture.connection.receiveScratchBytes == ReceiveScratch.floorWindow)
        }

        @Test("a connection whose peer really does send 16 KiB grows into it, then hands it back")
        func aBusyConnectionGrowsAndThenReclaims() async throws {
            let fixture = try Fixture()
            let payload = [UInt8](repeating: 0x5A, count: Self.serverCeiling)
            var grown = 0
            for _ in 0 ..< 8 where grown < Self.serverCeiling {
                fixture.send(payload)
                var buffer: [UInt8] = []
                try await Self.drain(fixture, into: &buffer, expected: payload.count)
                #expect(buffer.count == payload.count)
                grown = fixture.connection.receiveScratchBytes
            }
            #expect(grown == Self.serverCeiling, "the window never reached the ceiling")

            // Now the connection goes quiet, as a keep-alive peer does between requests. Each run of
            // quarter-full reads halves the window; three runs put it back on the floor.
            for _ in 0 ..< (4 * ReceiveScratch.shrinkRun) {
                fixture.send([0x2A])
                var buffer: [UInt8] = []
                try await Self.drain(fixture, into: &buffer, expected: 1)
            }
            #expect(fixture.connection.receiveScratchBytes == ReceiveScratch.floorWindow)
        }

        @Test("a payload larger than the window arrives whole across short reads")
        func aLargePayloadSurvivesTheShortReads() async throws {
            let fixture = try Fixture()
            // Deliberately not a multiple of the floor, so the last read is a partial one.
            let payload = (0 ..< 5_000).map { UInt8($0 % 251) }
            fixture.send(payload)

            var buffer: [UInt8] = []
            try await Self.drain(fixture, into: &buffer, expected: payload.count)
            #expect(buffer == payload)
        }

        // MARK: - Teardown: nothing to return twice, nothing to leak

        @Test("closing a connection twice is idempotent and leaves the scratch readable")
        func aDoubleCloseIsIdempotent() async throws {
            let fixture = try Fixture()
            fixture.send(Self.requestHead)
            var buffer: [UInt8] = []
            try await Self.drain(fixture, into: &buffer, expected: Self.requestHead.count)
            let resident = fixture.connection.receiveScratchBytes

            await fixture.connection.close()
            await fixture.connection.close()
            fixture.connection.cancel()

            // The scratch is the connection's own storage, so close neither returns it anywhere nor
            // invalidates it — the property a pooled buffer would have had to prove instead.
            #expect(fixture.connection.receiveScratchBytes == resident)
            await #expect(throws: (any Error).self) {
                _ = try await fixture.connection.receive(maxLength: Self.serverCeiling)
            }
        }

        @Test("cancelling a parked read leaves the scratch exactly where the last read left it")
        func aCancelledParkedReadLeavesTheScratchIntact() async throws {
            let fixture = try Fixture()
            fixture.send(Self.requestHead)
            var buffer: [UInt8] = []
            try await Self.drain(fixture, into: &buffer, expected: Self.requestHead.count)
            let resident = fixture.connection.receiveScratchBytes
            #expect(resident == ReceiveScratch.floorWindow)

            // Nothing more is buffered, so this read parks — then its own task is cancelled.
            let parked = Task {
                try await fixture.connection.receive(maxLength: Self.serverCeiling)
            }
            try await Task.sleep(for: .milliseconds(50))
            parked.cancel()
            await #expect(throws: (any Error).self) { try await parked.value }

            // A read torn down mid-park adapted nothing — the syscall never produced a count — so the
            // window is exactly where the last completed read left it.
            #expect(fixture.connection.receiveScratchBytes == resident)
        }

        @Test("an end-of-stream read does not resize the scratch under the caller")
        func anEndOfStreamReadLeavesTheWindowAlone() async throws {
            let fixture = try Fixture()
            fixture.send(Self.requestHead)
            var buffer: [UInt8] = []
            try await Self.drain(fixture, into: &buffer, expected: Self.requestHead.count)
            #expect(fixture.connection.receiveScratchBytes == ReceiveScratch.floorWindow)

            fixture.finish()
            let eof = try await fixture.connection.receive(maxLength: Self.serverCeiling)
            #expect(eof == nil)
            // Already on the floor, so the end-of-stream read's shrink tick cannot take it lower.
            #expect(fixture.connection.receiveScratchBytes == ReceiveScratch.floorWindow)
        }
    }

#endif
