//
//  ReadinessWaiterCollisionTests.swift
//  HTTPTransportTests
//
//  The reactor's readiness tables were `[Int32: @Sendable () -> Void]` — **one** handler per
//  descriptor per direction, installed with a plain subscript assignment. A second waiter parking on
//  the same descriptor in the same direction therefore *overwrote* the first, whose continuation was
//  then never resumed by anything: not by readiness, which had forgotten it, and not by
//  `closeDescriptor`, which also removes only one.
//
//  This is the third appearance of the same shape in this audit. ADD-P0.2 fixed it in
//  `POSIXDispatchConnection`, where a read and a write waiter shared one `Mutex<Waiter?>`; the fix
//  there split the slot by direction, which is exactly the right fix for *that* collision and no
//  defence at all against two waiters in the *same* direction.
//
//  It surfaced here from the portable-TLS serialization work, where both TLS byte pumps could park on
//  one socket's writability: the observed symptom was not corrupt output but a test exceeding its time
//  limit, because the dropped continuation simply never resumed. Serializing the TLS pumps removes one
//  caller that could do this. It does not make the loop safe for the next one, which is why the fix
//  belongs here rather than only there.
//
//  Readiness is level information, so waking every parked waiter is sound: each retries its syscall
//  and re-parks on `EAGAIN`.
//

import Darwin
import HTTPTestSupport
import Testing

@testable import HTTPTransport

@Suite("Reactor — two waiters on one descriptor (audit FLAKE-1 follow-up)", .realNetwork)
struct ReadinessWaiterCollisionTests {
    @Test("both waiters parked on one descriptor's readability are resumed")
    func readabilityWakesEveryWaiter() async throws {
        let loop = try KqueueEventLoop()
        loop.start()
        defer { loop.stop() }
        let pipe = try Self.makePipe()
        defer { close(pipe.write) }

        let woken = AsyncEventProbe<Int>()
        loop.waitReadable(pipe.read) { woken.record(1) }
        loop.waitReadable(pipe.read) { woken.record(2) }

        var byte: UInt8 = 0x41
        #expect(write(pipe.write, &byte, 1) == 1)

        // Two waiters, two resumptions. Before the fix the first was dropped on registration and this
        // wait timed out at one — the shape that made the TLS pumps hang rather than misbehave.
        let events = try await woken.wait(forAtLeast: 2)
        #expect(events.sorted() == [1, 2])
        loop.closeDescriptor(pipe.read)
    }

    /// Closing must unwind *every* parked waiter, not just the most recent one.
    ///
    /// This is the half that leaks: a waiter the readiness table has forgotten is not resumed by the
    /// close path either, so its task stays suspended for the process's life.
    @Test("closing a descriptor resumes every waiter parked on it")
    func closeUnwindsEveryWaiter() async throws {
        let loop = try KqueueEventLoop()
        loop.start()
        defer { loop.stop() }
        let pipe = try Self.makePipe()
        defer { close(pipe.write) }

        let woken = AsyncEventProbe<Int>()
        loop.waitReadable(pipe.read) { woken.record(1) }
        loop.waitReadable(pipe.read) { woken.record(2) }

        loop.closeDescriptor(pipe.read)  // closes and unwinds; no data ever arrives
        let events = try await woken.wait(forAtLeast: 2)
        #expect(events.sorted() == [1, 2])
    }

    /// A pipe, since it is readable exactly when written to and needs no peer to cooperate.
    private static func makePipe() throws -> (read: Int32, write: Int32) {
        var descriptors: [Int32] = [0, 0]
        let made = descriptors.withUnsafeMutableBufferPointer { buffer in
            pipe(buffer.baseAddress)
        }
        try #require(made == 0, "pipe(2) failed with errno \(errno)")
        return (descriptors[0], descriptors[1])
    }
}
