//
//  ConnectionDirectionOwnershipTests.swift
//  HTTPTransportTests
//
//  A raw connection is an ordered octet stream: TCP carries exactly one sequence space per direction
//  (RFC 9293 §3.1), so exactly one operation may own a direction at a time. Request parallelism belongs
//  ABOVE this seam — HTTP/2 stream multiplexing (RFC 9113 §5), HTTP/3's QUIC streams (RFC 9114 §2).
//
//  Nothing enforced that. `OnceResumer.reset` installed each new continuation over the pending one with
//  a plain assignment, and its own doc comment stated the invariant it did not enforce: "the caller
//  guarantees the previous continuation was already taken (ops are serialized on the connection)". The
//  displaced continuation was then resumed by nothing — not by readiness, which hands its result to the
//  survivor, and not by close, which finds only the survivor. The task stays suspended for the life of
//  the process (CWE-833, deadlock by lost wakeup).
//
//  This is the FOURTH appearance of the single-slot-waiter shape in this audit, and the first three
//  fixes are why it survived: ADD-P0.2 split a shared `Mutex<Waiter?>` by direction, the event loops
//  gained per-descriptor waiter lists, and each was correct one layer down while leaving the shape
//  intact one layer up. So these tests exercise the whole logical operation — readiness AND the scratch
//  copy-out, readiness AND every partial-write retry — rather than the readiness registration alone.
//
//  The full-duplex control (`receiveAndSendStayIndependent`) is the other half of the specification:
//  the two directions are independent domains, and a fix that put them behind one connection-wide lock
//  would trade this hang for a bottleneck on every connection in the server. It must stay green.
//
//  Standards: read()/write()/shutdown()/close() per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP framing
//  per RFC 9293. Readiness via BSD kqueue, so the suite self-gates to Darwin.
//

#if canImport(Darwin)

    import Darwin
    internal import Dispatch
    internal import Synchronization

    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite("Raw connection — one operation owner per direction (audit F-03)", .realNetwork)
    struct ConnectionDirectionOwnershipTests {
        /// The recorded marker for a receive that ended at end of stream rather than taking an octet.
        static let endOfStream = -1

        /// N concurrent receives must each run their OWN `read(2)` and resume with their own octet.
        ///
        /// The octets are written only after every task exists, so the operations demonstrably overlap;
        /// the oracle is the count, and a dropped continuation can only ever lower it. Against the
        /// single-slot resumer this reports "only 1 recorded" for every N.
        @Test(
            "every same-direction receive resumes with its own octet",
            .timeLimit(.minutes(1)),
            arguments: [2, 4, 8])
        func receivesResumeIndependently(_ concurrency: Int) async throws {
            let fixture = try Fixture()
            let taken = AsyncEventProbe<Int>()
            let readers = fixture.spawnReceives(concurrency, into: taken)
            defer { Self.cancel(readers) }
            try await fixture.settle()

            var octets = (0 ..< concurrency).map { UInt8(0x41 + $0) }
            #expect(write(fixture.client, &octets, octets.count) == octets.count)

            let recorded = try await taken.wait(forAtLeast: concurrency, timeout: .seconds(3))
            #expect(recorded.sorted() == octets.map(Int.init))
        }

        /// N concurrent sends must each drain fully, not just the last one to install a continuation.
        ///
        /// The send window is deliberately tiny, so every payload blocks partway and re-arms — this
        /// exercises the *partial-write retry* half of the operation, which is where a displaced
        /// continuation strands a half-written response.
        @Test(
            "every same-direction send completes and delivers its whole payload",
            .timeLimit(.minutes(2)),
            arguments: [2, 3])
        func sendsResumeIndependently(_ concurrency: Int) async throws {
            let fixture = try Fixture(window: 2_048)
            let completed = AsyncEventProbe<Int>()
            let senders = fixture.spawnSends(concurrency, into: completed)
            defer { Self.cancel(senders) }
            try await fixture.settle()

            let expected = Fixture.payload.count * concurrency
            let drained = fixture.drainPeer(untilAtLeast: expected)
            let finished = try await completed.wait(forAtLeast: concurrency, timeout: .seconds(10))
            #expect(finished.sorted() == Array(0 ..< concurrency))
            #expect(try await drained.wait(forAtLeast: 1, timeout: .seconds(10)).first == expected)
        }

        /// Receive and send are independent domains: a receive parked on a peer that never speaks must
        /// not delay a send.
        ///
        /// The control on the fix. One connection-wide actor or lock would serialize the two directions
        /// and hang this test — trading a lost wakeup for a bottleneck on every connection served.
        @Test(
            "a parked receive does not delay a send on the same connection",
            .timeLimit(.minutes(1)))
        func receiveAndSendStayIndependent() async throws {
            let fixture = try Fixture()
            let taken = AsyncEventProbe<Int>()
            let parked = fixture.spawnReceives(1, into: taken)
            defer { Self.cancel(parked) }
            try await fixture.settle()

            // The peer has sent nothing, so the receive above is still parked. A send must not wait
            // behind it.
            try await fixture.connection.send([0x5A])
            var echo: UInt8 = 0
            #expect(read(fixture.client, &echo, 1) == 1)
            #expect(echo == 0x5A)
            #expect(taken.isEmpty)
        }

        /// A receive cancelled while it is QUEUED behind another must throw and leave the owner alone.
        ///
        /// Cancelling a queued operation cannot tear the connection down: the operation ahead of it owns
        /// the direction and has framing in flight. Against the single-slot resumer the queued call had
        /// already displaced the owner's continuation and installed a per-park cancellation handler, so
        /// cancelling it closed the connection and stranded the owner.
        @Test(
            "cancelling a queued receive leaves the operation ahead of it intact",
            .timeLimit(.minutes(1)))
        func cancellingQueuedReceiveSparesTheOwner() async throws {
            let fixture = try Fixture()
            let taken = AsyncEventProbe<Int>()
            let owner = fixture.spawnReceives(1, into: taken)
            defer { Self.cancel(owner) }
            try await fixture.settle()

            let queued = Task { try await fixture.connection.receive(maxLength: 1) }
            try await fixture.settle()
            queued.cancel()
            await #expect(throws: CancellationError.self) { try await queued.value }

            var octet: UInt8 = 0x41
            #expect(write(fixture.client, &octet, 1) == 1)
            #expect(try await taken.wait(forAtLeast: 1, timeout: .seconds(3)) == [0x41])
        }

        /// Closing must unwind EVERY operation on the direction, owner and queued alike.
        ///
        /// The half that leaks: a continuation the resumer has forgotten is not resumed by the close
        /// path either. Only the survivor unwound; the rest stayed suspended.
        @Test(
            "closing unwinds every receive on the direction",
            .timeLimit(.minutes(1)),
            arguments: [2, 4])
        func closeUnwindsEveryReceive(_ concurrency: Int) async throws {
            let fixture = try Fixture()
            let settled = AsyncEventProbe<Int>()
            let readers = fixture.spawnReceives(concurrency, into: settled)
            defer { Self.cancel(readers) }
            try await fixture.settle()

            fixture.connection.cancel()
            let recorded = try await settled.wait(forAtLeast: concurrency, timeout: .seconds(3))
            #expect(recorded.count == concurrency)
        }

        /// A peer half-close (`shutdown(SHUT_WR)`) must be reported to every receive, not just one.
        ///
        /// EOF is sticky on a byte stream: each queued receive re-runs `read(2)` and sees the same
        /// zero-length result, so each returns `nil` rather than hanging on a stream that has ended.
        @Test(
            "every receive observes the peer's half-close",
            .timeLimit(.minutes(1)),
            arguments: [2, 4])
        func halfCloseReachesEveryReceive(_ concurrency: Int) async throws {
            let fixture = try Fixture()
            let settled = AsyncEventProbe<Int>()
            let readers = fixture.spawnReceives(concurrency, into: settled)
            defer { Self.cancel(readers) }
            try await fixture.settle()

            #expect(shutdown(fixture.client, SHUT_WR) == 0)
            let recorded = try await settled.wait(forAtLeast: concurrency, timeout: .seconds(3))
            #expect(recorded == Array(repeating: Self.endOfStream, count: concurrency))
        }

        /// A send to a peer that has hung up must FAIL, and so must everything queued behind it.
        ///
        /// `SO_NOSIGPIPE` is set on both ends of the fixture pair, so the write reports `EPIPE` instead
        /// of raising a fatal signal (audit T-F1) — the failure has to reach every waiting sender.
        @Test(
            "a send to a departed peer fails rather than hanging",
            .timeLimit(.minutes(1)),
            arguments: [2, 3])
        func departedPeerFailsEverySend(_ concurrency: Int) async throws {
            let fixture = try Fixture(window: 2_048)
            let settled = AsyncEventProbe<Int>()
            let senders = fixture.spawnSends(concurrency, into: settled)
            defer { Self.cancel(senders) }
            try await fixture.settle()

            fixture.closeClient()
            let recorded = try await settled.wait(forAtLeast: concurrency, timeout: .seconds(5))
            #expect(recorded.sorted() == Array(0 ..< concurrency))
        }

        /// Cancelling a send parked MID-PAYLOAD must unwind it and everything queued behind it.
        ///
        /// The partial-write case: the socket window is full, the payload is half on the wire, and the
        /// connection is torn down. A byte stream cannot abandon a half-written response and stay in
        /// sync, so teardown is the only honest outcome — and every sender on the direction must resume.
        @Test(
            "tearing down a partially-written send unwinds the whole direction",
            .timeLimit(.minutes(1)),
            arguments: [2, 3])
        func cancellingPartialWriteUnwindsTheDirection(_ concurrency: Int) async throws {
            let fixture = try Fixture(window: 2_048)
            let settled = AsyncEventProbe<Int>()
            let senders = fixture.spawnSends(concurrency, into: settled)
            try await fixture.settle()

            senders[0].cancel()
            fixture.connection.cancel()
            let recorded = try await settled.wait(forAtLeast: concurrency, timeout: .seconds(5))
            #expect(recorded.sorted() == Array(0 ..< concurrency))
        }

        /// A descriptor number the kernel hands back after a close must carry no state from the
        /// connection that used to hold it.
        ///
        /// The resumer is per connection, so a stale continuation cannot leak across an fd reuse — but
        /// only if the closed connection actually unwound everything it owned. Darwin hands out the
        /// lowest free descriptor, so the second fixture very likely lands on the first one's number;
        /// either way the fresh connection has to work.
        @Test(
            "a reused descriptor number carries no state from the closed connection",
            .timeLimit(.minutes(1)))
        func reusedDescriptorCarriesNoState() async throws {
            let settled = AsyncEventProbe<Int>()
            let first = try Fixture()
            let readers = first.spawnReceives(2, into: settled)
            try await first.settle()
            Self.cancel(readers)
            first.connection.cancel()
            first.closeClient()
            _ = try await settled.wait(forAtLeast: 2, timeout: .seconds(3))

            let second = try Fixture(loop: first.loop)
            var octet: UInt8 = 0x5A
            #expect(write(second.client, &octet, 1) == 1)
            #expect(try await second.connection.receive(maxLength: 1) == [0x5A])
        }

        /// Cancels every task in `tasks` — the teardown every test runs on its way out.
        private static func cancel(_ tasks: [Task<Void, Never>]) {
            for task in tasks {
                task.cancel()
            }
        }

        /// A socket pair, a kqueue loop and a connection over the server end — what every test builds on.
        ///
        /// Deliberately a class: it owns descriptors and a running loop thread, and `deinit` is the only
        /// place that can release them once a test body has thrown partway.
        private final class Fixture: Sendable {
            /// Comfortably larger than any `window` below, so a send blocks partway and re-arms.
            static let payload = [UInt8](repeating: 0x41, count: 128 * 1_024)

            let loop: KqueueEventLoop
            let connection: POSIXKqueueConnection
            let client: Int32
            private let ownsLoop: Bool
            private let clientClosed = Atomic<Bool>(false)

            /// Builds the pair and the connection; `window` shrinks both socket buffers so a modest
            /// payload blocks partway, and `loop` reuses an already-running loop.
            init(window: Int32? = nil, loop: KqueueEventLoop? = nil) throws {
                let running = try loop ?? KqueueEventLoop()
                self.ownsLoop = loop == nil
                if loop == nil {
                    running.start()
                }
                self.loop = running
                let pair = try Self.makeSocketPair(window: window)
                self.client = pair.client
                self.connection = POSIXKqueueConnection(
                    id: TransportConnectionID(1),
                    descriptor: pair.server,
                    peer: TransportAddress(host: "local", port: 0),
                    eventLoop: running
                )
            }

            deinit {
                connection.cancel()
                if !clientClosed.exchange(true, ordering: .acquiringAndReleasing) {
                    close(client)
                }
                if ownsLoop {
                    loop.stop()
                }
            }

            /// Closes the peer end early — the departed-peer / `EPIPE` setup.
            func closeClient() {
                if !clientClosed.exchange(true, ordering: .acquiringAndReleasing) {
                    close(client)
                }
            }

            /// Lets every spawned task reach its park, or its place in the queue behind the owner.
            ///
            /// There is no public "the operation is parked" hook on a `TransportConnection`, so this
            /// sequences SETUP only, exactly as the existing cancellation conformance probe does. Every
            /// oracle is event-driven: no octet is written and no close happens until this returns, so
            /// the operations demonstrably overlap, and a dropped continuation can only lower a count
            /// that is then waited for against its own timeout.
            func settle() async throws {
                try await Task.sleep(for: .milliseconds(150))
            }

            /// Spawns `count` receives, recording the octet each took (or ``endOfStream`` at EOF).
            func spawnReceives(
                _ count: Int,
                into probe: AsyncEventProbe<Int>
            ) -> [Task<Void, Never>] {
                (0 ..< count)
                    .map { _ in
                        Task {
                            let eof = ConnectionDirectionOwnershipTests.endOfStream
                            guard let chunk = try? await self.connection.receive(maxLength: 1)
                            else {
                                probe.record(eof)
                                return
                            }
                            probe.record(chunk.first.map(Int.init) ?? eof)
                        }
                    }
            }

            /// Spawns `count` sends of ``payload``, recording each sender's index as it settles.
            func spawnSends(_ count: Int, into probe: AsyncEventProbe<Int>) -> [Task<Void, Never>] {
                (0 ..< count)
                    .map { index in
                        Task {
                            try? await self.connection.send(Self.payload)
                            probe.record(index)
                        }
                    }
            }

            /// Drains the peer end off the cooperative pool until `total` octets have arrived.
            func drainPeer(untilAtLeast total: Int) -> AsyncEventProbe<Int> {
                let drained = AsyncEventProbe<Int>()
                let peer = client
                DispatchQueue.global(qos: .userInitiated)
                    .async {
                        var seen = 0
                        var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
                        while seen < total {
                            let count = read(peer, &buffer, buffer.count)
                            guard count > 0 else { break }
                            seen += count
                        }
                        drained.record(seen)
                    }
                return drained
            }

            private static func makeSocketPair(
                window: Int32?
            ) throws -> (server: Int32, client: Int32) {
                var descriptors = [Int32](repeating: 0, count: 2)
                let made = descriptors.withUnsafeMutableBufferPointer { buffer in
                    socketpair(AF_UNIX, SOCK_STREAM, 0, buffer.baseAddress)
                }
                try #require(made == 0, "socketpair(2) failed with errno \(errno)")
                POSIXSocket.setNonBlocking(descriptors[0])
                POSIXSocket.setNoSIGPIPE(descriptors[0])
                POSIXSocket.setNoSIGPIPE(descriptors[1])
                if var window {
                    let width = socklen_t(MemoryLayout<Int32>.size)
                    _ = setsockopt(descriptors[0], SOL_SOCKET, SO_SNDBUF, &window, width)
                    _ = setsockopt(descriptors[1], SOL_SOCKET, SO_RCVBUF, &window, width)
                }
                return (descriptors[0], descriptors[1])
            }
        }
    }

#endif
