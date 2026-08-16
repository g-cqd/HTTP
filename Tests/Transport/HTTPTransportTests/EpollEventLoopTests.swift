//
//  EpollEventLoopTests.swift
//  HTTPTransportTests
//
//  The first direct tests of ``EpollEventLoop`` — the Linux reactor that, until this branch, no gate
//  had ever built, let alone run.
//
//  Why this file exists at all: the epoll loop is a line-for-line mirror of ``KqueueEventLoop``, and
//  its Darwin twin is covered by `ReactorFairnessTests` and `ReadinessWaiterCollisionTests` — both of
//  which are `#if canImport(Darwin)` or kqueue-typed, so neither says anything about this file. Four
//  changes landed on the mirror without ever being compiled (the fairness quantum, the adaptive
//  receive scratch, the multi-waiter readiness tables, and the `ready` redeclaration those
//  introduced). The redeclaration was a hard build break; the other three are still taken on faith.
//  These tests convert three of them into assertions.
//
//  The claims, one per test, each phrased so that the PRE-fix implementation fails it:
//
//   - Two waiters on one descriptor in one direction both resume. The tables were
//     `[Int32: @Sendable () -> Void]`, one handler per fd per direction installed by subscript
//     assignment, so the second waiter silently dropped the first and its continuation was resumed by
//     nothing — a task suspended for the life of the process.
//   - The close sweep resumes ALL of them, for the same reason and on the other path.
//   - A one-shot firing in one direction re-arms for a waiter still parked in the other. This is the
//     `isEmpty == false` vs `!= nil` distinction: epoll keeps ONE registration per fd carrying a
//     combined mask, and an emptied waiter list is still a live dictionary entry.
//   - A refused registration returns false and drops its handler rather than parking behind a
//     registration that can never fire.
//   - The fairness quantum keeps a job flood from starving socket readiness (PERF-1, CWE-400).
//
//  Standards: epoll(7), eventfd(2), socketpair(2) per POSIX.1-2017 (IEEE Std 1003.1-2017).
//

#if canImport(Glibc)

    internal import Glibc
    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite("Reactor — the epoll loop (Linux mirror of KqueueEventLoop)")
    struct EpollEventLoopTests {
        /// The sentinel a readiness handler records, distinct from every job index.
        private static let readinessMarker = -1

        @Test(
            "two waiters on one descriptor both resume, in each direction", arguments: [true, false]
        )
        func waitersOnOneDescriptorResumeIndependently(readable: Bool) async throws {
            let loop = try EpollEventLoop()
            loop.start()
            defer { loop.stop() }
            let pair = try Self.socketPair()
            defer {
                close(pair.local)
                close(pair.peer)
            }

            let fired = AsyncEventProbe<Int>()
            // A fresh socketpair is immediately writable and not readable, so the readable leg is
            // driven by the peer write below and the writable leg fires on the first turn.
            for id in [1, 2] {
                let handler: @Sendable () -> Void = { fired.record(id) }
                let parked =
                    readable
                    ? loop.waitReadable(pair.local, handler)
                    : loop.waitWritable(pair.local, handler)
                #expect(parked, "the kernel refused a registration on a live descriptor")
            }
            if readable {
                var byte: UInt8 = 0x41
                #expect(write(pair.peer, &byte, 1) == 1)
            }

            // "only 1 recorded" is the pre-fix failure, on either leg.
            let seen = try await fired.wait(forAtLeast: 2)
            #expect(seen.sorted() == [1, 2])
        }

        @Test("closeDescriptor resumes every waiter parked on the descriptor, not just one")
        func closeResumesEveryParkedWaiter() async throws {
            let loop = try EpollEventLoop()
            loop.start()
            defer { loop.stop() }
            let pair = try Self.socketPair()
            defer { close(pair.peer) }  // `local` is closed by the loop's own sweep

            let fired = AsyncEventProbe<Int>()
            // Read waiters only: nothing has been written, so neither can be resumed by readiness and
            // the close sweep is provably the only thing that can complete them.
            for id in [1, 2, 3] {
                let parked = loop.waitReadable(pair.local) { fired.record(id) }
                #expect(parked)
            }
            loop.closeDescriptor(pair.local)

            let seen = try await fired.wait(forAtLeast: 3)
            #expect(seen.sorted() == [1, 2, 3])
        }

        @Test("a one-shot firing in one direction re-arms for a waiter still parked in the other")
        func firingOneDirectionRearmsTheOther() async throws {
            let loop = try EpollEventLoop()
            loop.start()
            defer { loop.stop() }
            let pair = try Self.socketPair()
            defer {
                close(pair.local)
                close(pair.peer)
            }

            let fired = AsyncEventProbe<Int>()
            let parkedRead = loop.waitReadable(pair.local) { fired.record(1) }
            let parkedWrite = loop.waitWritable(pair.local) { fired.record(2) }
            #expect(parkedRead)
            #expect(parkedWrite)

            // The socket is writable at once, so the write waiter fires first and `EPOLLONESHOT`
            // disarms the WHOLE descriptor — the read waiter survives only if `dispatch` re-arms it.
            let afterWrite = try await fired.wait(forAtLeast: 1)
            #expect(
                afterWrite == [2], "the writable leg should complete first on a fresh socketpair")

            var byte: UInt8 = 0x41
            #expect(write(pair.peer, &byte, 1) == 1)
            let seen = try await fired.wait(forAtLeast: 2)
            #expect(seen.sorted() == [1, 2])
        }

        @Test("a refused registration returns false and drops its handler")
        func refusedRegistrationIsReportedAndDropsTheHandler() async throws {
            let loop = try EpollEventLoop()
            loop.start()
            defer { loop.stop() }

            let fired = AsyncEventProbe<Int>()
            // -1 is never a valid descriptor, so `epoll_ctl` fails with EBADF deterministically —
            // unlike a closed fd number, which the kernel may already have reused.
            let refusedRead = loop.waitReadable(-1) { fired.record(1) }
            let refusedWrite = loop.waitWritable(-1) { fired.record(2) }
            #expect(refusedRead == false)
            #expect(refusedWrite == false)
            // The caller owns failing its own waiter; the loop must not have retained either handler.
            #expect(fired.events.isEmpty)
        }

        /// A job flood must not starve socket readiness — the PERF-1 quantum, as an ORDERING claim.
        ///
        /// Deliberately not a latency assertion. The budget is wall-clock (1 ms), but asserting on
        /// elapsed time would make this the kind of test that fails on a loaded box and teaches the
        /// reader to re-run. Instead the flood and the readiness handler record into one ordered
        /// probe: with the quantum, the loop breaks out of the drain and services readiness within a
        /// millisecond, so the marker lands near the FRONT. With an unbounded drain — the pre-PERF-1
        /// `while !isEmpty` — every job runs first and the marker is necessarily LAST. Those two
        /// outcomes are separated by the whole length of the flood, so no timing margin is involved.
        @Test(
            "a job flood does not starve socket readiness (PERF-1)",
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func jobFloodDoesNotStarveReadiness() async throws {
            let loop = try EpollEventLoop()
            loop.start()
            defer { loop.stop() }
            let pair = try Self.socketPair()
            defer {
                close(pair.local)
                close(pair.peer)
            }

            let jobCount = 2_000
            let ordering = AsyncEventProbe<Int>()
            for index in 0 ..< jobCount {
                Task(executorPreference: loop) {
                    // ~250 us of real work per job, so the flood is ~0.5 s — hundreds of quanta.
                    usleep(250)
                    ordering.record(index)
                }
            }
            // Park readiness and make it ready while the flood is still draining.
            let parked = loop.waitReadable(pair.local) { ordering.record(Self.readinessMarker) }
            #expect(parked)
            var byte: UInt8 = 0x41
            #expect(write(pair.peer, &byte, 1) == 1)

            let seen = try await ordering.wait(forAtLeast: jobCount + 1)
            let marker = try #require(seen.firstIndex(of: Self.readinessMarker))
            // Unbounded drain puts the marker at `jobCount`; the quantum puts it in the first
            // handful. A quarter of the flood is a bound neither implementation lands near.
            #expect(
                marker < jobCount / 4,
                "readiness was serviced only after \(marker) of \(jobCount) queued jobs"
            )
        }

        // MARK: - Harness

        /// A connected `AF_UNIX` stream pair: `local` is the descriptor under test.
        private static func socketPair() throws -> (local: Int32, peer: Int32) {
            var fds: [Int32] = [-1, -1]
            // Glibc vends SOCK_STREAM as the C enum `__socket_type` while `socketpair` takes Int32.
            let made = fds.withUnsafeMutableBufferPointer { buffer -> Bool in
                guard let base = buffer.baseAddress else {
                    return false
                }
                return socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, base) == 0
            }
            guard made else {
                throw TransportError.ioFailed("socketpair failed (errno \(errno))")
            }
            return (fds[0], fds[1])
        }
    }

#endif
