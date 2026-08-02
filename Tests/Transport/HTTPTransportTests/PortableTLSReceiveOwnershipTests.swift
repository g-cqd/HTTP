//
//  PortableTLSReceiveOwnershipTests.swift
//  HTTPTransportTests
//
//  Audit F-02: who owns the plaintext scratch between `SSL_read` and the copy-out of what it produced.
//
//  `receive(into:maxLength:)` used to serialize the decrypt, RELEASE `receivePump`, and only then copy
//  the produced octets out of the engine's shared scratch into the caller's buffer. A second receiver
//  taking the pump in that window decrypted over the same scratch, so the first caller copied out the
//  second's plaintext: one byte delivered twice, another never delivered. The fix makes decrypt and
//  copy-out one indivisible logical receive — the lease spans both, and the engine appends under the
//  same acquisition that decrypted.
//
//  `PortableTLSSerializationTests` carries the headline 8,192 one-byte proof. This suite is the
//  surface around it: the scratch-window boundaries, the end-of-stream and peer-close behaviour, a
//  peer that dribbles hard enough to force `WANT_READ` on nearly every receive, and cancellation.
//  Every assertion is a MULTISET comparison, because concurrent receives may legally complete in any
//  order and only a multiset distinguishes a reordering from a loss.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — the opt-in portable build (`HTTP_PORTABLE_TLS`).
//
//  Standards: TLS 1.3 (RFC 8446) — §6.1 close_notify is the clean end of stream asserted here, and
//  §4.6.3 removed renegotiation, which is why the `WANT_WRITE` arm of the decrypt loop is unreachable
//  on a 1.3 session (see ``dribbledDeliveryForcesWantReadWithoutLosingAByte``). CWE-362 (race on a
//  shared resource) over CWE-367 (time-of-check time-of-use).
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import Dispatch
    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS — receive scratch ownership (audit F-02)", .realNetwork)
    struct PortableTLSReceiveOwnershipTests {
        /// Concurrent receivers, chosen to exceed the one-holder-plus-one-waiter depth the exclusion
        /// is uncontended at — the defect needs a SECOND receiver in the window, and a deep queue
        /// makes that window far easier to hit on a lightly loaded host.
        private static let readers = 128

        /// 8,192 octets: every byte value exactly 32 times.
        private static let payload = PortableTLSLoopback.balancedPayload(repeats: 32)

        /// A payload sized so a run at `ceiling` performs a comparable number of receives whatever
        /// the ceiling is — roughly 256 of them, plus the ``readers`` that only ever see the close.
        ///
        /// A FIXED payload makes this suite progressively blinder as the ceiling rises: 8 KiB of
        /// plaintext at a 2 KiB ceiling is four receives in the whole run, and four receives almost
        /// never interleave. That is measured, not assumed — with the defect reinstated, a fixed
        /// 8 KiB payload against 8 readers caught it at ceilings 1 and 2,047 and missed it at 2,048
        /// and 2,049. Scaling the payload with the ceiling, and deepening the reader queue, holds the
        /// number of chances to observe the race roughly constant across the arguments.
        private static func payload(for ceiling: Int) -> [UInt8] {
            [UInt8](PortableTLSLoopback.balancedPayload(repeats: max(32, ceiling)))
        }

        /// The plaintext scratch's window boundary, and the values either side of it.
        ///
        /// ``ReceiveScratch`` reads into a window that starts at ``ReceiveScratch/floorWindow`` and
        /// doubles only on a read that fills it, so a ceiling at, just below, and just above the floor
        /// exercises three different relationships between the caller's request and the scratch's
        /// size — including the one where `SSL_read` fills the window exactly and the scratch grows
        /// underneath the very next receive.
        ///
        /// Their mutation sensitivity is not uniform, and saying so is worth more than implying it is.
        /// With the defect reinstated, ceilings 1, 2,047 and 2,049 fail on every run (3 of 3); ceiling
        /// 2,048 — the one case where the request and the window match exactly, so every `SSL_read`
        /// returns a full window and the readers fall into lockstep — passes. That argument therefore
        /// carries BEHAVIOURAL coverage of the exact-fit boundary, not race coverage; the race is
        /// covered by its three neighbours here and by the 8,192 one-byte proof in the sibling suite.
        private static let boundaries = [
            1,
            ReceiveScratch.floorWindow - 1,
            ReceiveScratch.floorWindow,
            ReceiveScratch.floorWindow + 1
        ]

        @Test(
            "concurrent receives at each scratch-window boundary deliver every byte exactly once",
            .timeLimit(.minutes(1)),
            .serialized,
            arguments: boundaries)
        func concurrentReceivesPreserveEveryByte(ceiling: Int) async throws {
            let harness = try Harness()
            defer { harness.tearDown() }
            let payload = Self.payload(for: ceiling)
            harness.startClient(writing: payload, thenClose: true)
            try await harness.connection.performHandshake()

            let collected = try await Self.drainConcurrently(harness.connection, ceiling: ceiling)
            #expect(collected.count == payload.count)
            #expect(
                PortableTLSLoopback.histogram(collected) == PortableTLSLoopback.histogram(payload)
            )
            await harness.connection.close()
        }

        @Test(
            "a peer that dribbles forces WANT_READ on nearly every receive and still loses nothing",
            .timeLimit(.minutes(1)))
        func dribbledDeliveryForcesWantReadWithoutLosingAByte() async throws {
            let harness = try Harness()
            defer { harness.tearDown() }
            // 32-octet pieces with a pause between each: the server's `SSL_read` finds the read BIO
            // empty far more often than not, so it takes the `.wantRead` arm — flush, then park on
            // readability — for most of the 256 pieces. That is the retry path the fix has to keep
            // sink-neutral: an outcome that produces no plaintext must leave the caller's buffer
            // exactly as it was, or a retry would append the previous read's octets a second time.
            //
            // The sibling `.wantWrite` arm is NOT forced here, and cannot be on this session: it is
            // reachable only from a TLS 1.2 renegotiation, which RFC 8446 §4.6.3 removed from 1.3.
            // Claiming coverage of it would be claiming coverage of dead code.
            harness.startClient(
                writing: Self.payload,
                thenClose: true,
                pieceOctets: 32,
                pauseMicros: 150
            )
            try await harness.connection.performHandshake()

            let collected = try await Self.drainConcurrently(harness.connection, ceiling: 64)
            #expect(collected.count == Self.payload.count)
            #expect(
                PortableTLSLoopback.histogram(collected)
                    == PortableTLSLoopback.histogram(Self.payload)
            )
            await harness.connection.close()
        }

        @Test(
            "a receive that ends at close_notify returns zero and appends nothing",
            .timeLimit(.minutes(1)))
        func endOfStreamAppendsNothingToTheCallersBuffer() async throws {
            let harness = try Harness()
            defer { harness.tearDown() }
            let greeting = Array("hello".utf8)
            harness.startClient(writing: greeting, thenClose: true)
            try await harness.connection.performHandshake()

            // The sentinel is the claim: a receive that produces nothing must leave the accumulator
            // BYTE-FOR-BYTE as it found it, not merely leave its count alone.
            var buffer = Array("sentinel-".utf8)
            let expected = buffer + greeting
            while buffer.count < expected.count {
                let count = try await harness.connection.receive(into: &buffer, maxLength: 4_096)
                guard count > 0 else {
                    break
                }
            }
            #expect(buffer == expected)
            // Past the end of stream now: every further receive is a no-op that reports zero.
            for _ in 0 ..< 3 {
                let count = try await harness.connection.receive(into: &buffer, maxLength: 4_096)
                #expect(count == 0)
                #expect(buffer == expected)
            }
            #expect(try await harness.connection.receive(maxLength: 4_096) == nil)
            #expect(!harness.connection.isReceivePumpHeld, "end of stream must hand the lease back")
            await harness.connection.close()
        }

        @Test(
            "a receive cancelled while parked on a silent peer appends nothing and frees the lease",
            .timeLimit(.minutes(1)))
        func aCancelledReceiveLeavesTheCallersBufferUntouched() async throws {
            let harness = try Harness()
            defer { harness.tearDown() }
            // The client handshakes and then says nothing at all, so the receive below reaches its
            // readability park and stays there until it is cancelled.
            harness.startClient(writing: [], thenClose: false)
            try await harness.connection.performHandshake()

            let connection = harness.connection
            let receiver = Task { () -> (Result<Int, any Error>, [UInt8]) in
                var buffer = Array("sentinel".utf8)
                do {
                    let count = try await connection.receive(into: &buffer, maxLength: 4_096)
                    return (.success(count), buffer)
                }
                catch {
                    return (.failure(error), buffer)
                }
            }
            // Wait for the receive to actually take the lease before cancelling, so this cancels a
            // PARKED receive rather than racing the task's first resumption.
            while !connection.isReceivePumpHeld {
                await Task.yield()
            }
            receiver.cancel()
            let (outcome, buffer) = await receiver.value

            #expect(throws: CancellationError.self) { try outcome.get() }
            #expect(
                buffer == Array("sentinel".utf8),
                "a cancelled receive must not half-fill the caller's buffer"
            )
            #expect(!connection.isReceivePumpHeld, "cancellation must hand the lease back")
            await connection.close()
        }

        // MARK: - Harness

        /// Runs ``PortableTLSConnection/receive(into:maxLength:)`` from ``readers`` concurrent tasks
        /// until every one of them has seen the end of stream, and returns everything they collected.
        ///
        /// Each reader accumulates into its OWN array, so the only shared mutable state on the path is
        /// the engine's plaintext scratch — which is precisely what is under test. Termination is by
        /// close_notify rather than by a byte count: a reader that is one short would otherwise park
        /// forever and turn a loss into a hang.
        private static func drainConcurrently(
            _ connection: PortableTLSConnection,
            ceiling: Int
        ) async throws -> [UInt8] {
            try await withThrowingTaskGroup(of: [UInt8].self) { group in
                for _ in 0 ..< Self.readers {
                    group.addTask {
                        var mine: [UInt8] = []
                        while true {
                            let count = try await connection.receive(
                                into: &mine,
                                maxLength: ceiling
                            )
                            guard count > 0 else {
                                return mine
                            }
                        }
                    }
                }
                var all: [UInt8] = []
                for try await slice in group {
                    all.append(contentsOf: slice)
                }
                return all
            }
        }

        /// A handshaken server connection with a raw libssl client on the other end of a socket pair.
        private final class Harness {
            let connection: PortableTLSConnection
            private let loop: TLSEventLoop
            private let serverContext: OpaquePointer
            private let clientDescriptor: Int32
            private let client: (ssl: OpaquePointer, context: OpaquePointer)
            /// Joins the background client before ``tearDown()`` frees the `SSL` it is still using.
            private let finished = DispatchSemaphore(value: 0)
            private var startedClient = false

            init() throws {
                let identity = try DevTLSIdentity.selfSigned()
                serverContext = try OpenSSLTLS.serverContext(identity)
                let pair = PortableTLSLoopback.makeSocketPair()
                clientDescriptor = pair.client
                loop = try TLSEventLoop()
                loop.start()
                connection = try PortableTLSLoopback.makeConnection(
                    serverContext,
                    descriptor: pair.server,
                    loop: loop
                )
                client = try PortableTLSLoopback.makeClient(descriptor: pair.client)
            }

            deinit {
                // Every handle is released in `tearDown()`, which the tests run from a `defer` while
                // the background client closure is known to have finished. Doing it here instead
                // would free the `SSL` on whichever thread dropped the last reference, possibly out
                // from under that closure.
            }

            /// Handshakes on a background thread, writes `bytes` (optionally in dribbled pieces), and
            /// optionally sends close_notify.
            func startClient(
                writing bytes: [UInt8],
                thenClose: Bool,
                pieceOctets: Int = .max,
                pauseMicros: UInt32 = 0
            ) {
                startedClient = true
                // `SSL` access is confined to this one background closure, which is what makes the
                // non-Sendable `OpaquePointer` safe to hand it — `nonisolated(unsafe)` states that.
                nonisolated(unsafe) let ssl = client.ssl
                let done = finished
                DispatchQueue.global(qos: .userInitiated)
                    .async {
                        defer { done.signal() }
                        guard CHTTPBoringSSL_SSL_connect(ssl) == 1 else {
                            return
                        }
                        var offset = 0
                        while offset < bytes.count {
                            let end = min(offset + max(1, pieceOctets), bytes.count)
                            let piece = Array(bytes[offset ..< end])
                            _ = piece.withUnsafeBytes {
                                CHTTPBoringSSL_SSL_write(ssl, $0.baseAddress, Int32($0.count))
                            }
                            offset = end
                            if pauseMicros > 0 {
                                usleep(pauseMicros)
                            }
                        }
                        if thenClose {
                            // RFC 8446 §6.1: close_notify is what turns the server's next `SSL_read`
                            // into a clean end of stream rather than an abrupt transport error.
                            _ = CHTTPBoringSSL_SSL_shutdown(ssl)
                        }
                    }
            }

            /// Joins the background client, then frees every handle in dependency order.
            func tearDown() {
                if startedClient {
                    // Joining before the frees below is what keeps this from racing the background
                    // closure. The timeout is a bound, not a measurement: the client either finished
                    // long ago or the connection is already torn down under it.
                    _ = finished.wait(timeout: .now() + .seconds(10))
                }
                CHTTPBoringSSL_SSL_free(client.ssl)
                CHTTPBoringSSL_SSL_CTX_free(client.context)
                _ = close(clientDescriptor)
                CHTTPBoringSSL_SSL_CTX_free(serverContext)
                loop.stop()
            }
        }
    }

#endif
