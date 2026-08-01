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
internal import Dispatch

import HTTPTestSupport
import Testing

@testable import HTTPTransport

@Suite("Reactor — two waiters on one descriptor (audit FLAKE-1 follow-up)", .realNetwork)
struct ReadinessWaiterCollisionTests {
    @Test(
        "two connection receives do not overwrite one another's cached continuation",
        .timeLimit(.minutes(1)))
    func connectionReceivesResumeIndependently() async throws {
        let loop = try KqueueEventLoop()
        loop.start()
        defer { loop.stop() }
        let pair = try Self.makeSocketPair()
        defer { close(pair.client) }
        let connection = POSIXKqueueConnection(
            id: TransportConnectionID(1),
            descriptor: pair.server,
            peer: TransportAddress(host: "local", port: 0),
            eventLoop: loop
        )
        defer { connection.cancel() }

        let completed = AsyncEventProbe<UInt8>()
        let first = Task {
            if let byte = try? await connection.receive(maxLength: 1)?.first {
                completed.record(byte)
            }
        }
        // There is no public "read is parked" hook. As in the existing cancellation conformance
        // probe, this delay sequences setup only; the completion oracle below is event-driven.
        try await Task.sleep(for: .milliseconds(100))
        let second = Task {
            if let byte = try? await connection.receive(maxLength: 1)?.first {
                completed.record(byte)
            }
        }
        try await Task.sleep(for: .milliseconds(100))

        var bytes: [UInt8] = [0x41, 0x42]
        #expect(write(pair.client, &bytes, bytes.count) == bytes.count)
        defer {
            first.cancel()
            second.cancel()
        }

        let received = try await completed.wait(forAtLeast: 2, timeout: .seconds(1))
        #expect(received.sorted() == bytes)
    }

    @Test(
        "two connection sends do not overwrite one another's cached continuation",
        .timeLimit(.minutes(1)))
    func connectionSendsResumeIndependently() async throws {
        let loop = try KqueueEventLoop()
        loop.start()
        defer { loop.stop() }
        let pair = try Self.makeSocketPair()
        defer { close(pair.client) }
        var small: Int32 = 2_048
        let width = socklen_t(MemoryLayout<Int32>.size)
        _ = setsockopt(pair.server, SOL_SOCKET, SO_SNDBUF, &small, width)
        _ = setsockopt(pair.client, SOL_SOCKET, SO_RCVBUF, &small, width)
        let connection = POSIXKqueueConnection(
            id: TransportConnectionID(1),
            descriptor: pair.server,
            peer: TransportAddress(host: "local", port: 0),
            eventLoop: loop
        )
        defer { connection.cancel() }

        let payload = [UInt8](repeating: 0x41, count: 128 * 1_024)
        let completed = AsyncEventProbe<Int>()
        let first = Task {
            try? await connection.send(payload)
            completed.record(1)
        }
        try await Task.sleep(for: .milliseconds(100))
        let second = Task {
            try? await connection.send(payload)
            completed.record(2)
        }
        try await Task.sleep(for: .milliseconds(100))

        // Both sends now exceed the deliberately tiny socket window and are parked. Drain the peer so
        // every registered writability handler gets a chance to finish its own operation.
        let drained = AsyncEventProbe<Int>()
        DispatchQueue.global(qos: .userInitiated)
            .async {
                var total = 0
                var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
                while total < payload.count * 2 {
                    let count = read(pair.client, &buffer, buffer.count)
                    guard count > 0 else { break }
                    total += count
                }
                drained.record(total)
            }
        defer {
            first.cancel()
            second.cancel()
        }

        let senders = try await completed.wait(forAtLeast: 2, timeout: .seconds(2))
        #expect(senders.sorted() == [1, 2])
        #expect(try await drained.wait(forAtLeast: 1).first == payload.count * 2)
    }

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

    private static func makeSocketPair() throws -> (server: Int32, client: Int32) {
        var descriptors = [Int32](repeating: 0, count: 2)
        let made = descriptors.withUnsafeMutableBufferPointer { buffer in
            socketpair(AF_UNIX, SOCK_STREAM, 0, buffer.baseAddress)
        }
        try #require(made == 0, "socketpair(2) failed with errno \(errno)")
        POSIXSocket.setNonBlocking(descriptors[0])
        return (descriptors[0], descriptors[1])
    }
}
