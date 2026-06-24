//
//  BackboneConformanceTests.swift
//  HTTPTransportTests
//
//  One conformance battery run against EVERY socket backbone via `TransportFactory`, so all backbones
//  are validated *equally* on the behaviors that matter — ephemeral-port binding, a loopback
//  round-trip, cancellation of a stalled receive, and clean shutdown — instead of each backbone owning
//  an ad-hoc, differently-sized test. The in-memory `fake` (no socket) and the QUIC backbones (a
//  separate `QUICServerTransport` protocol) keep their own suites.
//

import HTTPTestSupport
internal import Network
import Testing

@testable import HTTPTransport

@Suite("Transport backbone conformance — every socket backbone, the same battery")
struct BackboneConformanceTests {
    /// Every real socket backbone (the fake binds no port; the QUIC backbones are a separate protocol).
    static let socketBackbones: [TransportBackbone] = [
        .networkFramework, .posixKqueue, .posixDispatch, .swiftSystem
    ]

    private func makeTransport(_ backbone: TransportBackbone) -> any ServerTransport {
        TransportFactory.make(TransportConfiguration(port: 0, backbone: backbone))
    }

    @Test(
        "binds a non-zero ephemeral port after start",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func bindsEphemeralPort(_ backbone: TransportBackbone) async throws {
        let transport = makeTransport(backbone)
        _ = try await transport.start()
        #expect(transport.boundPort != 0, "\(backbone.rawValue) bound no port")
        await transport.shutdown()
    }

    @Test(
        "accepts a connection and round-trips bytes over loopback",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func loopbackRoundTrip(_ backbone: TransportBackbone) async throws {
        let transport = makeTransport(backbone)
        let stream = try await transport.start()
        try await assertLoopbackEcho(stream: stream, port: transport.boundPort)
        await transport.shutdown()
    }

    @Test(
        "cancellation unblocks a stalled receive instead of deadlocking",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func cancellationUnblocksStalledReceive(_ backbone: TransportBackbone) async throws {
        let transport = makeTransport(backbone)
        let stream = try await transport.start()

        // A client that connects but never sends, so the server's read blocks indefinitely.
        let endpointPort = try #require(NWEndpoint.Port(rawValue: transport.boundPort))
        let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
        client.start(queue: .global())

        var iterator = stream.makeAsyncIterator()
        let connection = try #require(await iterator.next())

        let receiveTask = Task { try await connection.receive(maxLength: 64) }
        // Give recv(2) a moment to actually park in the kernel before cancelling — there is no portable
        // hook for "the syscall is now blocked". The deadlock detection below is probe-driven, not a
        // timed race: the probe `wait` returns the instant the read unblocks, and only elapses its
        // real-time deadline (throwing) if it truly deadlocks.
        try await Task.sleep(for: .milliseconds(200))
        receiveTask.cancel()

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

    @Test(
        "shutdown finishes the connection stream", .timeLimit(.minutes(1)),
        arguments: socketBackbones)
    func shutdownFinishesStream(_ backbone: TransportBackbone) async throws {
        let transport = makeTransport(backbone)
        let stream = try await transport.start()
        await transport.shutdown()
        // After shutdown the stream must finish (its async iterator returns nil), not hang forever.
        let drained = AsyncEventProbe<Void>()
        let drainer = Task {
            for await _ in stream {}  // drains to completion once the transport finishes the stream
            drained.record(())
        }
        _ = try await drained.wait(forAtLeast: 1, timeout: .seconds(3))
        await drainer.value
    }
}
