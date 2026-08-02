//
//  DirectionOwnerTests.swift
//  HTTPTransportTests
//
//  The ownership contract itself, tested away from any socket — the part that can be driven exactly
//  rather than raced. `ConnectionDirectionOwnershipTests` proves the four raw backbones behave; this
//  proves the invariant they rest on, and it does so deterministically: `waitForQueued(atLeast:)` lets
//  a test assert AT the contended moment instead of sleeping and hoping to catch it. A test that only
//  *may* interleave is not a regression test.
//
//  The one that matters most is `resumerRefusesDisplacement`. It is the machine-checked form of the
//  sentence the old `OnceResumer.reset` carried in its doc comment and did not enforce — "the caller
//  guarantees the previous continuation was already taken (ops are serialized on the connection)".
//  Restore the unconditional assignment and this test does not merely fail: the incumbent continuation
//  is resumed by nothing and the test hangs to its time limit, which is exactly the production symptom
//  (CWE-833, deadlock by lost wakeup).
//
//  Standards: TCP carries one sequence space per direction (RFC 9293 §3.1); request concurrency belongs
//  above this seam — HTTP/2 stream multiplexing (RFC 9113 §5), HTTP/3 over QUIC streams (RFC 9114 §2).
//

import HTTPTestSupport
import Testing

@testable import HTTPTransport

@Suite("Raw connection — the direction-ownership contract (audit F-03)")
struct DirectionOwnerTests {
    /// The resumer must refuse to displace a pending continuation, and the INCUMBENT must survive.
    ///
    /// The whole defect in one assertion. The old `reset` overwrote the slot, so the incumbent was
    /// resumed by nothing — not by readiness, which had handed its result to the survivor, and not by
    /// close, which finds only the survivor. Here the intruder is failed at once and the incumbent is
    /// still there to be resumed, which is what makes the contract enforceable rather than described.
    ///
    /// Both resumptions are harvested through a ``ResumptionOracle`` rather than `await`ed directly,
    /// which is what makes the mutation BOUNDED. Restore the unconditional overwrite and the displaced
    /// task is parked on a continuation nothing will resume and nothing can cancel: awaiting it here
    /// would hang the process to the `.timeLimit` below and report only that it did. See
    /// ``ResumptionOracle`` for why an in-process watchdog is sufficient and a subprocess is not.
    @Test("the resumer refuses to displace a pending continuation", .timeLimit(.minutes(1)))
    func resumerRefusesDisplacement() async throws {
        let resumer = OnceResumer<Int>()
        let oracle = ResumptionOracle(direction: .inbound, operation: "receive")
        let installed = AsyncEventProbe<Int>()
        let incumbent = Task {
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Int, any Error>) in
                #expect(resumer.claim(continuation))
                installed.record(1)
            }
        }
        _ = try await installed.wait(forAtLeast: 1)

        // Recorded rather than asserted inside the task, so the refusal is observable from out here
        // BEFORE anything resumes — the intruder must be failed by `claim` itself, not by the resume
        // below. Under the overwrite mutation this is the first thing that fails, and it fails fast.
        let refusal = AsyncEventProbe<Bool>()
        let intruder = Task {
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Int, any Error>) in
                refusal.record(resumer.claim(continuation))
            }
        }
        #expect(try await refusal.wait(forAtLeast: 1) == [false])

        // The incumbent was never touched: readiness still finds the continuation it installed.
        resumer.resume(returning: 42)
        let rejected = await oracle.resumption(of: "the displaced intruder") {
            try await intruder.value
        }
        #expect(throws: DirectionOwnershipViolation.self) { try rejected?.get() }
        let survived = await oracle.resumption(of: "the incumbent owner") {
            try await incumbent.value
        }
        #expect(try survived?.get() == 42)
    }

    /// A resumer resumes at most once, however many times its callback fires.
    ///
    /// Readiness handlers re-arm on `EAGAIN` and the close sweep may race them, so the second and third
    /// resumal are ordinary events on this path, not errors. The slot empties on the first take, which
    /// is also what lets the NEXT operation claim it.
    @Test("a claimed continuation is resumed exactly once", arguments: [2, 3, 8])
    func resumesAtMostOnce(_ resumals: Int) async throws {
        let resumer = OnceResumer<Int>()
        let installed = AsyncEventProbe<Int>()
        let parked = Task {
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Int, any Error>) in
                #expect(resumer.claim(continuation))
                installed.record(1)
            }
        }
        _ = try await installed.wait(forAtLeast: 1)

        for value in 0 ..< resumals {
            resumer.resume(returning: value)
        }
        #expect(try await parked.value == 0)  // the first resumal wins; the rest are no-ops
    }

    /// A second operation is QUEUED behind the owner, never admitted alongside it.
    ///
    /// Deterministic by construction: `waitForQueued(atLeast:)` returns exactly when the second caller
    /// is registered, so the assertions below run at the contended moment rather than near it.
    @Test("a second operation queues behind the owner", .timeLimit(.minutes(1)))
    func secondOperationQueuesBehindTheOwner() async throws {
        let owner = DirectionOwner<Int>()
        let entered = AsyncEventProbe<Int>()
        let release = AsyncEventProbe<Int>()
        let holder = Task {
            try await owner.withOwnership { _ in
                entered.record(1)
                _ = try await release.wait(forAtLeast: 1, timeout: .seconds(10))
            }
        }
        _ = try await entered.wait(forAtLeast: 1)
        #expect(owner.isOwned)

        let second = Task { try await owner.withOwnership { _ in entered.record(2) } }
        try await owner.waitForQueued(atLeast: 1)
        #expect(owner.queuedOperations == 1)
        #expect(entered.count == 1)  // still queued: the second body has NOT run

        release.record(1)
        try await holder.value
        try await second.value
        #expect(entered.events == [1, 2])
        #expect(!owner.isOwned)
        #expect(owner.queuedOperations == 0)
    }

    /// Queued operations are admitted in arrival order, so a stream of later arrivals cannot starve one
    /// already waiting.
    @Test(
        "queued operations are admitted first-in, first-out",
        .timeLimit(.minutes(1)),
        arguments: [2, 4, 8])
    func queuedOperationsAreAdmittedInOrder(_ concurrency: Int) async throws {
        let owner = DirectionOwner<Int>()
        let entered = AsyncEventProbe<Int>()
        let release = AsyncEventProbe<Int>()
        let holder = Task {
            try await owner.withOwnership { _ in
                entered.record(0)
                _ = try await release.wait(forAtLeast: 1, timeout: .seconds(10))
            }
        }
        _ = try await entered.wait(forAtLeast: 1)

        var queued: [Task<Void, Never>] = []
        for index in 1 ... concurrency {
            queued.append(
                Task {
                    do {
                        try await owner.withOwnership { _ in entered.record(index) }
                    }
                    catch {
                        Issue.record(error, "queued operation \(index) did not run")
                    }
                }
            )
            // One at a time, so arrival order is the order asserted below rather than a race.
            try await owner.waitForQueued(atLeast: index)
        }

        release.record(1)
        try await holder.value
        for task in queued {
            await task.value
        }
        #expect(entered.events == Array(0 ... concurrency))
    }

    /// A caller cancelled while merely QUEUED throws and leaves the owner untouched.
    ///
    /// The connection-level consequence: cancelling a receive that never started must not tear the
    /// connection down, because the operation ahead of it owns the direction and has framing in flight.
    @Test("cancelling a queued operation spares the owner", .timeLimit(.minutes(1)))
    func cancellingAQueuedOperationSparesTheOwner() async throws {
        let owner = DirectionOwner<Int>()
        let entered = AsyncEventProbe<Int>()
        let release = AsyncEventProbe<Int>()
        let holder = Task {
            try await owner.withOwnership { _ in
                entered.record(1)
                _ = try await release.wait(forAtLeast: 1, timeout: .seconds(10))
            }
        }
        _ = try await entered.wait(forAtLeast: 1)

        let queued = Task { try await owner.withOwnership { _ in entered.record(2) } }
        try await owner.waitForQueued(atLeast: 1)
        queued.cancel()
        await #expect(throws: CancellationError.self) { try await queued.value }
        #expect(owner.isOwned)  // the holder still owns the direction
        #expect(owner.queuedOperations == 0)

        release.record(1)
        try await holder.value
        #expect(entered.events == [1])  // the cancelled body never ran
    }

    /// The two directions are independent: owning one must not gate the other.
    ///
    /// The unit-level twin of the full-duplex control in `ConnectionDirectionOwnershipTests`. A fix that
    /// reached for one connection-wide exclusion would hang here.
    @Test("holding one direction does not gate the other", .timeLimit(.minutes(1)))
    func directionsAreIndependent() async throws {
        let inbound = DirectionOwner<Int>()
        let outbound = DirectionOwner<Void>()
        let entered = AsyncEventProbe<Int>()
        let release = AsyncEventProbe<Int>()
        let holder = Task {
            try await inbound.withOwnership { _ in
                entered.record(1)
                _ = try await release.wait(forAtLeast: 1, timeout: .seconds(10))
            }
        }
        _ = try await entered.wait(forAtLeast: 1)

        try await outbound.withOwnership { _ in entered.record(2) }
        #expect(entered.events == [1, 2])
        #expect(inbound.isOwned)
        #expect(!outbound.isOwned)

        release.record(1)
        try await holder.value
    }

    /// The uncontended claim → resume cycle allocates nothing.
    ///
    /// The per-operation cost of the contract on the single-reader/single-writer path, measured where
    /// it can be measured exactly: the body is synchronous, which is what `mallocDelta` requires, and
    /// it is warmed once first so lazy initialization is not charged to the measurement. Counting is
    /// per measuring thread, so a suite running in parallel cannot inflate it.
    @Test("the uncontended claim-and-resume cycle allocates nothing")
    func claimAndResumeAllocateNothing() async throws {
        let resumer = OnceResumer<Int>()
        _ = try await Self.cycle(resumer)  // warm up: lazy init is not part of the measurement
        let measured = try await Self.cycle(resumer)
        // Exactly zero where counting works, and explicitly `nil` where it does not (a sanitized build,
        // or a non-Darwin host) — so the claim can never pass vacuously because the oracle went blind.
        #expect(measured == (allocationCountingAvailable ? 0 : nil))
    }

    /// The uncontended path never grows the exclusion's FIFO.
    ///
    /// The queue is an `Array` that starts as the shared empty singleton, so "never appended to" is
    /// "never allocated". This is the structural half of the allocation claim, and it covers the async
    /// path that `mallocDelta` cannot see: `mallocDelta` needs a synchronous body, and counts only the
    /// measuring thread's allocations.
    @Test("an uncontended direction never grows its queue", arguments: [1, 16, 256])
    func uncontendedOwnershipNeverQueues(_ operations: Int) async throws {
        let owner = DirectionOwner<Int>()
        for _ in 0 ..< operations {
            try await owner.withOwnership { _ in
                #expect(owner.isOwned)
                #expect(owner.queuedOperations == 0)
            }
        }
        #expect(!owner.isOwned)
        #expect(owner.queuedOperations == 0)
    }

    /// One claim → resume round trip, returning the heap allocations it made (`nil` where counting is
    /// unavailable — a sanitized build, or a non-Darwin host).
    ///
    /// The closure `withUnsafeThrowingContinuation` runs is synchronous, which is the only place on
    /// this path where a real `UnsafeContinuation` exists and a synchronous measurement is possible.
    private static func cycle(_ resumer: OnceResumer<Int>) async throws -> Int? {
        nonisolated(unsafe) var delta: Int?
        _ = try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Int, any Error>) in
            delta = mallocDelta {
                resumer.claim(continuation)
                resumer.resume(returning: 1)
            }
        }
        return delta
    }
}
