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
//  PORTABLE ON PURPOSE. The defect is not a kqueue defect: `POSIXEpollConnection` carries the same
//  `OnceResumer` shape, and the Linux-restoration work named the Darwin-only
//  `ReadinessWaiterCollisionTests` "THE LARGEST COVERAGE DEBT IN THIS LIST" for exactly that reason —
//  two red cases describing a live Linux defect that no Linux test observed. So the fixture below is
//  the only platform-specific part: the reactor and the raw connection are picked by `#if`, and all
//  nine tests run unchanged against BOTH mirrors. That needs no `Package.swift` entry, which matters
//  because the Linux test-graph exclusions belong to another agent this week.
//
//  Standards: read()/write()/shutdown()/close()/socketpair() per POSIX.1-2017 (IEEE Std 1003.1-2017);
//  TCP framing per RFC 9293. Readiness via BSD kqueue (Darwin) or epoll(7) (Linux).
//

#if canImport(Darwin) || canImport(Glibc)

    internal import Dispatch
    internal import Synchronization

    #if canImport(Darwin)
        import Darwin
    #elseif canImport(Glibc)
        import Glibc
    #endif

    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite("Raw connection — one operation owner per direction (audit F-03)", .realNetwork)
    struct ConnectionDirectionOwnershipTests {
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
            let fixture = try RawConnectionFixture()
            let taken = AsyncEventProbe<Int>()
            let readers = fixture.spawnReceives(concurrency, into: taken)
            defer { RawConnectionFixture.cancel(readers) }
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
            let fixture = try RawConnectionFixture(window: 2_048)
            let completed = AsyncEventProbe<Int>()
            let senders = fixture.spawnSends(concurrency, into: completed)
            defer { RawConnectionFixture.cancel(senders) }
            try await fixture.settle()

            let expected = RawConnectionFixture.payload.count * concurrency
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
            let fixture = try RawConnectionFixture()
            let taken = AsyncEventProbe<Int>()
            let parked = fixture.spawnReceives(1, into: taken)
            defer { RawConnectionFixture.cancel(parked) }
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
            let fixture = try RawConnectionFixture()
            let taken = AsyncEventProbe<Int>()
            let owner = fixture.spawnReceives(1, into: taken)
            defer { RawConnectionFixture.cancel(owner) }
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
            let fixture = try RawConnectionFixture()
            let settled = AsyncEventProbe<Int>()
            let readers = fixture.spawnReceives(concurrency, into: settled)
            defer { RawConnectionFixture.cancel(readers) }
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
            let fixture = try RawConnectionFixture()
            let settled = AsyncEventProbe<Int>()
            let readers = fixture.spawnReceives(concurrency, into: settled)
            defer { RawConnectionFixture.cancel(readers) }
            try await fixture.settle()

            // `SHUT_WR` imports as Int32 on Darwin and as Int on Glibc — normalize for `shutdown`.
            #expect(shutdown(fixture.client, Int32(SHUT_WR)) == 0)
            let recorded = try await settled.wait(forAtLeast: concurrency, timeout: .seconds(3))
            #expect(
                recorded == Array(repeating: RawConnectionFixture.endOfStream, count: concurrency))
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
            let fixture = try RawConnectionFixture(window: 2_048)
            let settled = AsyncEventProbe<Int>()
            let senders = fixture.spawnSends(concurrency, into: settled)
            defer { RawConnectionFixture.cancel(senders) }
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
            let fixture = try RawConnectionFixture(window: 2_048)
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
            let first = try RawConnectionFixture()
            let readers = first.spawnReceives(2, into: settled)
            try await first.settle()
            RawConnectionFixture.cancel(readers)
            first.connection.cancel()
            first.closeClient()
            _ = try await settled.wait(forAtLeast: 2, timeout: .seconds(3))

            let second = try RawConnectionFixture(loop: first.loop)
            var octet: UInt8 = 0x5A
            #expect(write(second.client, &octet, 1) == 1)
            #expect(try await second.connection.receive(maxLength: 1) == [0x5A])
        }
    }

#endif
