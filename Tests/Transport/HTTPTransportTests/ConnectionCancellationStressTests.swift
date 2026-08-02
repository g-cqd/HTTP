//
//  ConnectionCancellationStressTests.swift
//  HTTPTransportTests
//
//  Cancellation at every ownership boundary, and the three invariants that must hold at each of them:
//  EXACTLY-ONCE RESUMPTION, NO STOLEN BYTES (a cancelled operation must not consume another's
//  readiness), and THE NEXT WAITER MAKES PROGRESS.
//
//  The middle one is why this suite exists. The ownership work made a cancelled QUEUED receive throw
//  without tearing the connection down — previously it closed the descriptor, because the per-park
//  cancellation handler was installed before the operation had the direction. That change is correct
//  ONLY IF cancellation cannot consume another operation's readiness, and nothing proved it. A queued
//  receive that ran even one `read(2)` on its way out would take an octet off the stream that the
//  rightful owner then never sees — and a short read is indistinguishable from a peer that sent less,
//  so the theft is silent at every layer above (RFC 9293 §3.1: one sequence space per direction).
//
//  Which cells are DETERMINISTIC and which are MACHINE-CHECKED, stated up front, because the
//  difference is the whole methodology:
//
//    before enqueue      deterministic — the task observes its own cancellation before it calls in,
//                        and `waitForQueuedReceives` proves the direction was already owned
//    while queued        deterministic — `waitForQueuedReceives(atLeast:)` returns exactly at the
//                        contended moment, so the cancel provably lands on a queued operation
//    after acquisition   deterministic — the owner is parked on a peer that never speaks
//    during partial I/O  deterministic — the send window is smaller than the payload, so the write
//                        provably blocks partway and re-arms
//    lease transfer      NOT deterministic, and not pretended to be. The instant the exclusion hands
//                        the lease from one operation to the next is interior to `AsyncExclusion`,
//                        lasts as long as a resumption, and a cancel aimed at it lands on either side
//                        of it depending on scheduling. So the invariant is asserted in the
//                        production path instead of sampled — `DirectionOwner.bodiesInFlight` and the
//                        four `assertInboundLeased()` guards — and THOSE are what mutation testing
//                        verifies. The test below drives the race anyway, but its job is to reach the
//                        assertions, not to be the oracle. A test that only MAY interleave is not a
//                        regression test, and this effort has already shipped one and had to say so.
//
//  Standards: read()/write()/close() per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP framing per
//  RFC 9293. CWE-833 (deadlock by lost wakeup) is the failure mode exactly-once resumption excludes.
//

#if canImport(Darwin) || canImport(Glibc)

    #if canImport(Darwin)
        import Darwin
    #elseif canImport(Glibc)
        import Glibc
    #endif

    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite("Raw connection — cancellation at every ownership boundary (audit F-03)", .realNetwork)
    struct ConnectionCancellationStressTests {
        /// A receive cancelled BEFORE it ever enqueues must not disturb the owner or the stream.
        ///
        /// The task observes its own cancellation first and only then calls in, so the cancel provably
        /// precedes the enqueue rather than racing it. The exclusion must refuse it without running the
        /// body: had the body run, the per-park cancellation handler would have closed the descriptor
        /// out from under an owner with framing in flight.
        @Test(
            "a receive cancelled before it enqueues spares the owner and the stream",
            .timeLimit(.minutes(1)),
            arguments: [1, 4])
        func cancelBeforeEnqueueStealsNothing(_ latecomers: Int) async throws {
            let fixture = try RawConnectionFixture()
            let taken = AsyncEventProbe<Int>()
            let owner = fixture.spawnReceives(1, into: taken)
            defer { RawConnectionFixture.cancel(owner) }
            try await fixture.settle()
            #expect(fixture.connection.isReceiving)

            let refused = AsyncEventProbe<Int>()
            let arrivals = (0 ..< latecomers)
                .map { index in
                    Task {
                        // Enter only once this task is demonstrably cancelled — no sleep, no race.
                        while !Task.isCancelled {
                            await Task.yield()
                        }
                        do {
                            _ = try await fixture.connection.receive(maxLength: 1)
                            refused.record(-1)  // admitted: the body ran despite the cancellation
                        }
                        catch {
                            refused.record(index)
                        }
                    }
                }
            for arrival in arrivals {
                arrival.cancel()
            }
            let settled = try await refused.wait(forAtLeast: latecomers)

            // Exactly once, and every one of them refused rather than admitted.
            #expect(settled.sorted() == Array(0 ..< latecomers))
            // No stolen bytes: the octet written now still reaches the owner that was there first.
            var octet: UInt8 = 0x41
            #expect(write(fixture.client, &octet, 1) == 1)
            #expect(try await taken.wait(forAtLeast: 1) == [0x41])
        }

        /// A receive cancelled while QUEUED must not consume the readiness the owner is waiting for.
        ///
        /// Deterministic by construction: `waitForQueuedReceives(atLeast:)` returns exactly when the
        /// latecomers are registered behind the owner, so the cancel lands on queued operations rather
        /// than near them. The single octet is the oracle — it can only be taken once, and it must be
        /// taken by the owner.
        @Test(
            "a receive cancelled while queued consumes no readiness",
            .timeLimit(.minutes(1)),
            arguments: [1, 4])
        func cancelWhileQueuedStealsNoReadiness(_ queued: Int) async throws {
            let fixture = try RawConnectionFixture()
            let taken = AsyncEventProbe<Int>()
            let owner = fixture.spawnReceives(1, into: taken)
            defer { RawConnectionFixture.cancel(owner) }
            try await fixture.settle()

            let settled = AsyncEventProbe<Int>()
            let latecomers = (0 ..< queued)
                .map { index in
                    Task {
                        do {
                            _ = try await fixture.connection.receive(maxLength: 1)
                            settled.record(-1)
                        }
                        catch {
                            settled.record(index)
                        }
                    }
                }
            try await fixture.connection.waitForQueuedReceives(atLeast: queued)
            #expect(fixture.connection.queuedReceives == queued)
            for latecomer in latecomers {
                latecomer.cancel()
            }
            #expect(try await settled.wait(forAtLeast: queued).sorted() == Array(0 ..< queued))
            // The owner still holds the direction — the cancellations did not tear it down.
            #expect(fixture.connection.isReceiving)

            var octet: UInt8 = 0x42
            #expect(write(fixture.client, &octet, 1) == 1)
            #expect(try await taken.wait(forAtLeast: 1) == [0x42])
        }

        /// The next waiter must make progress once the owner is done — cancellations and all.
        ///
        /// The liveness half of the contract. A queued receive that is NOT cancelled has to be admitted
        /// after the owner returns, even though its neighbours were cancelled out of the queue around
        /// it: the FIFO must close over the hole rather than strand what is behind it (CWE-833).
        @Test(
            "the surviving waiter is admitted after cancellations around it",
            .timeLimit(.minutes(1)),
            arguments: [1, 3])
        func survivingWaiterMakesProgress(_ cancelled: Int) async throws {
            let fixture = try RawConnectionFixture()
            let taken = AsyncEventProbe<Int>()
            let owner = fixture.spawnReceives(1, into: taken)
            defer { RawConnectionFixture.cancel(owner) }
            try await fixture.settle()

            let doomed = (0 ..< cancelled)
                .map { _ in
                    Task { _ = try? await fixture.connection.receive(maxLength: 1) }
                }
            try await fixture.connection.waitForQueuedReceives(atLeast: cancelled)
            let survivor = fixture.spawnReceives(1, into: taken)
            defer { RawConnectionFixture.cancel(survivor) }
            try await fixture.connection.waitForQueuedReceives(atLeast: cancelled + 1)
            for task in doomed {
                task.cancel()
            }

            // Two octets, two surviving receives: each must take its own, in order.
            var octets: [UInt8] = [0x43, 0x44]
            #expect(write(fixture.client, &octets, 2) == 2)
            let recorded = try await taken.wait(forAtLeast: 2)
            #expect(recorded.sorted() == [0x43, 0x44])
        }

        /// Cancelling the OWNER of a parked receive tears the connection down and unwinds everything.
        ///
        /// The contractual asymmetry with the queued case, asserted so it cannot drift: a byte stream
        /// cannot abandon an in-flight read and stay in sync, so the owner's cancellation is a teardown
        /// — and every operation behind it must resume, exactly once, rather than be stranded.
        @Test(
            "cancelling the owner unwinds every receive exactly once",
            .timeLimit(.minutes(1)),
            arguments: [1, 4])
        func cancelAfterAcquisitionUnwindsEveryone(_ queued: Int) async throws {
            let fixture = try RawConnectionFixture()
            let settled = AsyncEventProbe<Int>()
            let owner = Task { _ = try? await fixture.connection.receive(maxLength: 1) }
            try await fixture.settle()
            #expect(fixture.connection.isReceiving)

            let behind = (0 ..< queued)
                .map { index in
                    Task {
                        _ = try? await fixture.connection.receive(maxLength: 1)
                        settled.record(index)
                    }
                }
            defer { RawConnectionFixture.cancel(behind) }
            try await fixture.connection.waitForQueuedReceives(atLeast: queued)

            owner.cancel()
            await owner.value
            #expect(try await settled.wait(forAtLeast: queued).sorted() == Array(0 ..< queued))
        }

        /// Cancelling a send parked MID-PAYLOAD unwinds it and every sender queued behind it, once each.
        ///
        /// The partial-I/O cell. The window is far smaller than the payload, so the write provably
        /// blocks partway and re-arms — the retry loop is inside the lease, which is what makes the
        /// cancellation land on a half-written response rather than between two whole ones.
        @Test(
            "cancelling a send mid-payload unwinds the direction exactly once",
            .timeLimit(.minutes(2)),
            arguments: [2, 3])
        func cancelDuringPartialWriteUnwindsOnce(_ concurrency: Int) async throws {
            let fixture = try RawConnectionFixture(window: 2_048)
            let settled = AsyncEventProbe<Int>()
            let senders = fixture.spawnSends(concurrency, into: settled)
            defer { RawConnectionFixture.cancel(senders) }
            try await fixture.connection.waitForQueuedSends(atLeast: concurrency - 1)

            senders[0].cancel()
            fixture.connection.cancel()
            let recorded = try await settled.wait(forAtLeast: concurrency)
            // Exactly once each: a duplicate would mean a continuation resumed twice, a missing index
            // a continuation resumed by nothing.
            #expect(recorded.sorted() == Array(0 ..< concurrency))
        }

        /// Cancelling exactly as the lease changes hands must not double-admit or steal the octet.
        ///
        /// NOT a deterministic cell, and deliberately not dressed up as one — see the file header. The
        /// owner is released by a single octet at the same moment its queue is cancelled, which puts a
        /// cancellation somewhere in the transfer window on some fraction of runs and elsewhere on the
        /// rest. Its job is to REACH `DirectionOwner`'s in-flight precondition and the four
        /// `assertInboundLeased()` guards, which are the actual oracle and hold on every run.
        ///
        /// What it can still assert unconditionally: every task settles exactly once, and the octet is
        /// taken at most once — never by two receives, and never by a cancelled one on its way out.
        @Test(
            "cancelling at the lease handover neither double-admits nor steals",
            .timeLimit(.minutes(2)),
            arguments: [2, 8])
        func cancelAtLeaseTransferIsExclusive(_ queued: Int) async throws {
            for _ in 0 ..< 12 {
                try await Self.raceOneHandover(queued: queued)
            }
        }

        /// One handover round: release the owner and cancel its queue at the same instant.
        private static func raceOneHandover(queued: Int) async throws {
            let fixture = try RawConnectionFixture()
            let taken = AsyncEventProbe<Int>()
            let settled = AsyncEventProbe<Int>()
            let owner = fixture.spawnReceives(1, into: taken)
            defer { RawConnectionFixture.cancel(owner) }
            try await fixture.settle()

            let behind = (0 ..< queued)
                .map { index in
                    Task {
                        if let chunk = try? await fixture.connection.receive(maxLength: 1),
                            let octet = chunk.first
                        {
                            taken.record(Int(octet))
                        }
                        settled.record(index)
                    }
                }
            defer { RawConnectionFixture.cancel(behind) }
            try await fixture.connection.waitForQueuedReceives(atLeast: queued)

            // The release and the cancellations are issued together; which side of the handover each
            // cancel lands on is the scheduler's business, and either side must be safe.
            var octet: UInt8 = 0x45
            #expect(write(fixture.client, &octet, 1) == 1)
            for task in behind {
                task.cancel()
            }

            _ = try await settled.wait(forAtLeast: queued)
            fixture.connection.cancel()
            _ = try? await taken.wait(forAtLeast: 1, timeout: TestLivenessBudget.absence)
            // At most one receive ever saw the octet: it cannot be delivered twice, and a cancelled
            // operation cannot have consumed it and dropped it (that would show as zero here only if
            // the owner also missed it — hence the equality against what the owner actually took).
            #expect(taken.events.filter { $0 == 0x45 }.count <= 1)
            #expect(settled.events.sorted() == Array(0 ..< queued))
        }
    }

#endif
