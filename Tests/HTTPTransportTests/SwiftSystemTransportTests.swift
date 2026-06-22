//
//  SwiftSystemTransportTests.swift
//  HTTPTransportTests
//
//  Loopback integration test for the apple/swift-system backbone (POSIX sockets + FileDescriptor).
//

import HTTPTestSupport
internal import Network
import Testing

@testable import HTTPTransport

@Suite("swift-system backbone — loopback I/O")
struct SwiftSystemTransportTests {

    @Test("accepts a connection and round-trips bytes over loopback", .timeLimit(.minutes(1)))
    func loopbackRoundTrip() async throws {
        let transport = SwiftSystemTransport(
            configuration: TransportConfiguration(port: 0, backbone: .swiftSystem))
        let stream = try await transport.start()
        try await assertLoopbackEcho(stream: stream, port: transport.boundPort)
        await transport.shutdown()
    }

    @Test(
        "cancellation unblocks a stalled receive instead of deadlocking",
        .timeLimit(.minutes(1)))
    func cancelUnblocksStalledReceive() async throws {
        let transport = SwiftSystemTransport(
            configuration: TransportConfiguration(port: 0, backbone: .swiftSystem))
        let stream = try await transport.start()

        // A client that connects but never sends, so the server's read blocks indefinitely.
        let endpointPort = try #require(NWEndpoint.Port(rawValue: transport.boundPort))
        let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
        client.start(queue: .global())

        var iterator = stream.makeAsyncIterator()
        let connection = try #require(await iterator.next())

        let receiveTask = Task { try await connection.receive(maxLength: 64) }
        // Inherent to a real-socket test: give the recv(2) a moment to actually park in the kernel
        // before cancelling — there is no portable hook for "the syscall is now blocked". This is the
        // one unavoidable real delay; the deadlock detection below is probe-driven, not a timed race.
        try await Task.sleep(for: .milliseconds(200))
        receiveTask.cancel()

        // With the shutdown(2) fix the cancelled read returns promptly; a deadlock would hang it.
        // Record completion into a probe: `wait` returns the instant the recv unblocks, and only
        // elapses its real-time deadline (throwing AsyncEventProbeTimeoutError) if it truly deadlocks.
        let unblocked = AsyncEventProbe<Void>()
        let joiner = Task {
            _ = try? await receiveTask.value
            unblocked.record(())
        }
        _ = try await unblocked.wait(forAtLeast: 1, timeout: .seconds(3))
        await joiner.value

        await connection.close()
        client.cancel()
        await transport.shutdown()
    }
}
