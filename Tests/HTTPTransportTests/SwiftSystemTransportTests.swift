//
//  SwiftSystemTransportTests.swift
//  HTTPTransportTests
//
//  Loopback integration test for the apple/swift-system backbone (POSIX sockets + FileDescriptor).
//

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
        try await Task.sleep(for: .milliseconds(200))  // let the read block in the kernel
        receiveTask.cancel()

        // With the shutdown(2) fix the cancelled read returns promptly; the deadlock would hang it.
        let unblocked = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                _ = try? await receiveTask.value
                return true
            }
            group.addTask {
                try? await Task.sleep(for: .seconds(3))
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        #expect(unblocked, "cancelled receive deadlocked behind the serial-queue close")

        await connection.close()
        client.cancel()
        await transport.shutdown()
    }
}
