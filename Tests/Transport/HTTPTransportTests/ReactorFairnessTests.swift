//
//  ReactorFairnessTests.swift
//  HTTPTransportTests
//
//  PERF-1 — the reactor drained its inbox `while !isEmpty` and its listener until `EAGAIN`, with no job
//  or time budget. Connections are pinned to a loop for life, so one saturating source held the loop
//  thread for as long as it had work and every other socket on that reactor waited behind it; a burst
//  of preferred-executor jobs could starve socket readiness outright (CWE-400 — the work is admitted,
//  so the only thing that degrades is everyone else's latency).
//
//  The drain also copied its arrays out under the lock and then called `removeAll(keepingCapacity:)`
//  on a now non-uniquely-referenced buffer, so the capacity it asked to keep was reallocated on every
//  single turn. Both are measured below.
//

#if canImport(Darwin)

    import Darwin
    import HTTPTestSupport
    import Synchronization
    import Testing

    @testable import HTTPTransport

    @Suite("Reactor fairness — one busy source may not starve the loop (PERF-1)")
    struct ReactorFairnessTests {
        /// How many jobs the feeder submits per round, and how long each occupies the loop thread.
        private static let jobsPerRound = 128
        private static let jobSpinNanoseconds: UInt64 = 25_000

        /// A latch the feeder polls, so the job source runs until the test stops it.
        ///
        /// The flood must be *unbounded* for the assertion to mean anything: with a fixed job count it
        /// can finish before readiness is even armed — which is how a first version of this test failed
        /// under `--parallel` while the code under test was correct. Un-budgeted, the loop would never
        /// look at the readiness set again while this is set, so ANY finite latency proves the quantum.
        private final class Latch: Sendable {
            private let raised = Mutex(true)
            var isRaised: Bool { raised.withLock(\.self) }

            func lower() { raised.withLock { $0 = false } }

            deinit {
                // No teardown beyond ARC.
            }
        }

        /// Burns roughly `nanoseconds` on the calling thread without sleeping, so the job genuinely
        /// occupies the loop rather than yielding it back.
        private static func spin(_ nanoseconds: UInt64) {
            let until = ReactorQuantum.nanoseconds() &+ nanoseconds
            while ReactorQuantum.nanoseconds() < until {
                // Busy-wait: a sleep would hand the loop thread back, which is the opposite of the
                // saturating source under test.
            }
        }

        @Test(
            "a saturating job source does not stop a second socket being serviced",
            .timeLimit(.minutes(1)))
        func aJobFloodDoesNotStarveReadiness() async throws {
            let loop = try KqueueEventLoop()
            loop.start()
            defer { loop.stop() }

            var pair: [Int32] = [-1, -1]
            #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
            defer {
                close(pair[0])
                close(pair[1])
            }

            let readableAt = AsyncEventProbe<UInt64>()
            let latch = Latch()
            let flood = Task.detached {
                await withTaskExecutorPreference(loop) {
                    while latch.isRaised {
                        await withDiscardingTaskGroup { group in
                            for _ in 0 ..< Self.jobsPerRound {
                                group.addTask { Self.spin(Self.jobSpinNanoseconds) }
                            }
                        }
                    }
                }
            }
            defer {
                latch.lower()
                flood.cancel()
            }

            // Let the flood take the loop thread before the second socket asks for anything, so the
            // readiness registration lands while the loop is provably busy.
            try await Task.sleep(for: .milliseconds(20))
            let armed = ReactorQuantum.nanoseconds()
            #expect(loop.waitReadable(pair[0]) { readableAt.record(ReactorQuantum.nanoseconds()) })
            var byte: UInt8 = 0x2A
            #expect(write(pair[1], &byte, 1) == 1)

            // THE assertion: this returns at all. The feeder keeps the inbox non-empty for as long as
            // the latch is raised, so an un-budgeted drain would never return to the readiness set and
            // this socket would be starved indefinitely.
            let observed = try await readableAt.wait(forAtLeast: 1, timeout: .seconds(20))
            let latency = observed[0] &- armed
            #expect(latch.isRaised, "the fixture must still be saturating the loop")
            // And the latency is a small multiple of the quantum rather than unbounded. Deliberately
            // generous: this host runs concurrent agents, so the number is not decision-grade — its
            // only job is to separate "bounded" from "starved".
            #expect(
                latency < 200 * ReactorQuantum.drainNanoseconds,
                "readiness took \(latency) ns, over 200 quanta"
            )
            // Stop the feeder and WAIT for it here rather than leaving the `defer` to fire and forget:
            // a detached task busy-spinning a core after this test returns is CPU the rest of a
            // `--parallel` run has to share, and the accept/loopback suites are already load-sensitive.
            latch.lower()
            await flood.value
        }

        /// The copy-out shape the drain used to have against the swap it uses now.
        ///
        /// `let taken = inbox` does not copy elements — it retains the same buffer, so the immediately
        /// following `removeAll(keepingCapacity: true)` finds a non-unique reference and must allocate
        /// a fresh one. The `keepingCapacity` intent was defeated on every drain. Swapping with a
        /// loop-owned scratch leaves both arrays uniquely referenced, so the capacity is genuinely
        /// reused and a steady-state drain allocates nothing.
        @Test("swapping the inbox reuses capacity where copying it out reallocated every turn")
        func theDrainSwapReusesCapacity() {
            guard allocationCountingAvailable else {
                return  // Darwin-only malloc hook
            }
            let batch = 256
            var copyInbox: [Int] = []
            var swapInbox: [Int] = []
            var swapScratch: [Int] = []

            // One turn of the old shape: producers fill the inbox, the loop copies it out, then
            // empties the inbox "keeping capacity" — which it cannot, the copy still holds the buffer.
            func copyTurn() {
                for value in 0 ..< batch {
                    copyInbox.append(value)
                }
                let taken = copyInbox
                copyInbox.removeAll(keepingCapacity: true)
                for value in taken where value < 0 {
                    fatalError("unreachable — the batch is only consumed to keep it alive")
                }
            }

            // One turn of the new shape: the same fill, then a swap with the loop-owned scratch, so
            // both arrays stay uniquely referenced.
            func swapTurn() {
                for value in 0 ..< batch {
                    swapInbox.append(value)
                }
                swap(&swapInbox, &swapScratch)
                for value in swapScratch where value < 0 {
                    fatalError("unreachable — the batch is only consumed to keep it alive")
                }
                swapScratch.removeAll(keepingCapacity: true)
            }

            // Both reach their steady-state capacity here; only what happens afterwards is the drain.
            for _ in 0 ..< 8 {
                copyTurn()
                swapTurn()
            }

            let turns = 64
            let copyCost = mallocDelta { for _ in 0 ..< turns { copyTurn() } }
            let swapCost = mallocDelta { for _ in 0 ..< turns { swapTurn() } }

            // Exactly one allocation saved per drain turn — the buffer `removeAll(keepingCapacity:)`
            // was forced to replace because the copy still referenced the old one. The DIFFERENCE is
            // what is asserted, because it is the same in both build configurations: release measures
            // 64 vs 0, debug 49280 vs 49216, where the shared 49216 is `-Onone` charging ~3
            // allocations to each `append` and says nothing about either drain shape.
            #expect(
                (copyCost ?? 0) - (swapCost ?? 0) == turns,
                "expected one saved allocation per turn; copy \(copyCost ?? -1), swap \(swapCost ?? -1)"
            )
            #if !DEBUG
                #expect(
                    swapCost == 0,
                    "the swap drain allocated \(swapCost ?? -1) time(s) in \(turns) turns"
                )
            #endif
        }
    }

#endif
