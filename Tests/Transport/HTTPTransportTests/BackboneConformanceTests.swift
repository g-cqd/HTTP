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

    private func makeTransport(_ backbone: TransportBackbone) throws -> any ServerTransport {
        try TransportFactory.make(TransportConfiguration(port: 0, backbone: backbone))
    }

    @Test(
        "binds a non-zero ephemeral port after start",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func bindsEphemeralPort(_ backbone: TransportBackbone) async throws {
        let transport = try makeTransport(backbone)
        _ = try await transport.start()
        #expect(transport.boundPort != 0, "\(backbone.rawValue) bound no port")
        await transport.shutdown()
    }

    @Test(
        "accepts a connection and round-trips bytes over loopback",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func loopbackRoundTrip(_ backbone: TransportBackbone) async throws {
        let transport = try makeTransport(backbone)
        let stream = try await transport.start()
        try await assertLoopbackEcho(stream: stream, port: transport.boundPort)
        await transport.shutdown()
    }

    @Test(
        "scatter-gather send(head, body) delivers head then body intact (writev path)",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func scatterGatherRoundTrip(_ backbone: TransportBackbone) async throws {
        let transport = try makeTransport(backbone)
        let stream = try await transport.start()
        // A 4 KiB body forces a genuine two-iovec writev and a multi-chunk client read.
        let head = Array("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n".utf8)
        let body = [UInt8](repeating: UInt8(ascii: "x"), count: 4_096)
        try await assertLoopbackScatterGather(
            stream: stream, port: transport.boundPort, head: head, body: body
        )
        await transport.shutdown()
    }

    @Test(
        "cancellation unblocks a stalled receive instead of deadlocking",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func cancellationUnblocksStalledReceive(_ backbone: TransportBackbone) async throws {
        let transport = try makeTransport(backbone)
        let stream = try await transport.start()

        // A client that connects but never sends, so the server's read blocks indefinitely.
        let endpointPort = try #require(NWEndpoint.Port(rawValue: transport.boundPort))
        let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
        client.start(queue: .global())

        var iterator = stream.makeAsyncIterator()
        let connection = try #require(await iterator.next())

        // The server hoists one connection-wide handler onto the serve task (audit CC4): cancelling it
        // closes the fd via `connection.cancel()`, which unblocks a stalled receive. This test drives
        // that server-level path explicitly; the bare child-task contract (the transport's own
        // per-park handler) is covered separately below.
        let receiveTask = Task {
            try await withTaskCancellationHandler {
                try await connection.receive(maxLength: 64)
            } onCancel: {
                connection.cancel()
            }
        }
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
        "a BARE child-task cancel unblocks a parked receive (the receive contract, S1 regression)",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func childTaskCancelUnblocksParkedReceive(_ backbone: TransportBackbone) async throws {
        let transport = try makeTransport(backbone)
        let stream = try await transport.start()

        // A client that connects but never sends, so the server's read parks indefinitely.
        let endpointPort = try #require(NWEndpoint.Port(rawValue: transport.boundPort))
        let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
        client.start(queue: .global())

        var iterator = stream.makeAsyncIterator()
        let connection = try #require(await iterator.next())

        // NO manual cancellation handler: exactly the shape of the server's idle watchdog, which
        // cancels the serve-loop CHILD task — the serve-task-level `cancel()` handler never fires, so
        // the transport itself must honor the cancel (the documented TransportConnection contract).
        // Before the per-park handlers landed, the real-socket backbones parked here forever.
        let receiveTask = Task {
            try await connection.receive(maxLength: 64)
        }
        // Give the receive a moment to actually park before cancelling — there is no portable hook
        // for "the continuation is now parked". The detection below is probe-driven, not a timed race.
        try await Task.sleep(for: .milliseconds(200))
        receiveTask.cancel()

        let unblocked = AsyncEventProbe<Void>()
        let joiner = Task {
            // The contract: a cancel-torn receive surfaces the standard cancellation signal.
            await #expect(throws: CancellationError.self) {
                try await receiveTask.value
            }
            unblocked.record(())
        }
        _ = try await unblocked.wait(forAtLeast: 1, timeout: .seconds(3))
        await joiner.value

        await connection.close()
        client.cancel()
        await transport.shutdown()
    }

    @Test(
        "a BARE child-task cancel also unblocks the parked scratch receive(into:) path",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func childTaskCancelUnblocksParkedScratchReceive(_ backbone: TransportBackbone) async throws {
        let transport = try makeTransport(backbone)
        let stream = try await transport.start()

        let endpointPort = try #require(NWEndpoint.Port(rawValue: transport.boundPort))
        let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
        client.start(queue: .global())

        var iterator = stream.makeAsyncIterator()
        let connection = try #require(await iterator.next())

        // The scratch overload is the server's hot read path (audit P1) — its parked phase must honor
        // a bare child-task cancel exactly like `receive(maxLength:)` (the S1 regression shape).
        let receiveTask = Task { () -> Int in
            var buffer: [UInt8] = []
            return try await connection.receive(into: &buffer, maxLength: 64)
        }
        try await Task.sleep(for: .milliseconds(200))
        receiveTask.cancel()

        let unblocked = AsyncEventProbe<Void>()
        let joiner = Task {
            await #expect(throws: CancellationError.self) {
                try await receiveTask.value
            }
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
        let transport = try makeTransport(backbone)
        let stream = try await transport.start()
        await transport.shutdown()
        // After shutdown the stream must finish (its async iterator returns nil), not hang forever.
        let drained = AsyncEventProbe<Void>()
        let drainer = Task {
            // Drains to completion once the transport finishes the stream.
            for await _ in stream {
                // No per-element work: draining is the goal.
            }
            drained.record(())
        }
        _ = try await drained.wait(forAtLeast: 1, timeout: .seconds(3))
        await drainer.value
    }
}
