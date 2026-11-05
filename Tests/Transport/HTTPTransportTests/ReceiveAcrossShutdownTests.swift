//
//  ReceiveAcrossShutdownTests.swift
//  HTTPTransportTests
//
//  A connection can outlive its transport's `shutdown()`: a server stopping while it still serves one. Its parked
//  receive must still return when its task is cancelled. On the reactor backbones it did not: once the loop
//  thread had exited, the cancel's close and the receive's resumption were queued to a loop nobody drained
//  (`KqueueEventLoop`, shared by posixKqueue and swiftSystem, and its Linux twin `EpollEventLoop`). Every socket
//  backbone of the platform runs the case, with a raw `socket(2)` client so the file builds on Linux too.
//

import HTTPTestSupport
import Testing

@testable import HTTPTransport

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

@Suite("A receive parked across the transport's shutdown", .realNetwork)
struct ReceiveAcrossShutdownTests {
    #if canImport(Darwin)
        static let backbones: [TransportBackbone] = [
            .networkFramework, .posixKqueue, .posixDispatch, .swiftSystem
        ]
    #else
        static let backbones: [TransportBackbone] = [.posixEpoll]
    #endif

    @Test(
        "a cancel still unblocks a receive parked across the transport's shutdown",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)),
        arguments: backbones
    )
    func cancelUnblocksReceiveParkedAcrossShutdown(_ backbone: TransportBackbone) async throws {
        let configuration = TransportConfiguration(port: 0, backbone: backbone)
        let transport = try TransportFactory.make(configuration)
        let stream = try await transport.start()
        // A client that connects and never sends, so the server's read parks.
        let client = openLoopbackConnection(to: transport.boundPort)
        try #require(client >= 0)
        defer { close(client) }
        var iterator = stream.makeAsyncIterator()
        let connection = try #require(await iterator.next())

        let receiveTask = Task { try await connection.receive(maxLength: 64) }
        // No portable hook for "the continuation is now parked"; the detection below is probe-driven.
        try await Task.sleep(for: .milliseconds(200))
        await transport.shutdown()
        receiveTask.cancel()

        let unblocked = AsyncEventProbe<Void>()
        let joiner = Task {
            _ = try? await receiveTask.value
            unblocked.record(())
        }
        _ = try await unblocked.wait(forAtLeast: 1)
        await joiner.value
        await connection.close()
    }
}
