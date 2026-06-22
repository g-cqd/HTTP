//
//  TransportBenchmarks.swift
//  HTTPBenchmarks
//
//  Every ``TransportBackbone``. The four socket backbones bind an ephemeral loopback port and echo
//  bytes back over an established connection (steady-state round-trip throughput; connection setup is
//  excluded from measurement via `startMeasurement()`). The in-memory `fake` backbone measures the
//  bare async send/receive abstraction overhead.
//
//  Live sockets need the SwiftPM sandbox disabled:
//      swift package --package-path Benchmarks --disable-sandbox benchmark --filter 'transport/*'
//

import Benchmark
import Foundation
import HTTPCore
import HTTPTransport
import Network

func registerTransportBenchmarks() {
    Benchmark("transport/fake/abstraction") { benchmark in
        for _ in benchmark.scaledIterations {
            let connection = FakeConnection(id: TransportConnectionID(0), inbound: transportPayload)
            blackHole(try? await connection.receive(maxLength: transportPayload.count))
            try? await connection.send(transportPayload)
        }
    }

    let socketBackbones: [TransportBackbone] = [
        .networkFramework, .posixKqueue, .posixDispatch, .swiftSystem,
    ]
    for backbone in socketBackbones {
        Benchmark("transport/\(backbone.rawValue)/echo") { benchmark in
            guard let (transport, boundPort) = makeSocketTransport(backbone) else { return }
            let stream: AsyncStream<any TransportConnection>
            do {
                stream = try await transport.start()
            } catch {
                return
            }
            let server = Task { await echoServer(stream) }
            let port = boundPort()
            guard port != 0, let client = startClient(port: port) else {
                await transport.shutdown()
                server.cancel()
                return
            }

            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                await clientSend(client, transportPayload)
                blackHole(await clientReceive(client, maxLength: 4096))
            }
            benchmark.stopMeasurement()

            client.cancel()
            await transport.shutdown()
            server.cancel()
            _ = await server.value
        }
    }
}

// MARK: - Server side (echo over the transport abstraction)

private func makeSocketTransport(
    _ backbone: TransportBackbone
) -> (any ServerTransport, () -> UInt16)? {
    let configuration = TransportConfiguration(port: 0, backbone: backbone)
    switch backbone {
    case .networkFramework:
        let transport = NetworkFrameworkTransport(configuration: configuration)
        return (transport, { transport.boundPort })
    case .posixKqueue:
        let transport = POSIXKqueueTransport(configuration: configuration)
        return (transport, { transport.boundPort })
    case .posixDispatch:
        let transport = POSIXDispatchTransport(configuration: configuration)
        return (transport, { transport.boundPort })
    case .swiftSystem:
        let transport = SwiftSystemTransport(configuration: configuration)
        return (transport, { transport.boundPort })
    case .fake:
        return nil
    }
}

private func echoServer(_ stream: AsyncStream<any TransportConnection>) async {
    var iterator = stream.makeAsyncIterator()
    guard let connection = await iterator.next() else { return }
    while true {
        // `receive` returns `[UInt8]?`; `try?` flattens it, so nil means EOF or error → stop.
        guard let chunk = try? await connection.receive(maxLength: 65_536) else { break }
        if chunk.isEmpty { continue }  // no data yet, keep waiting
        try? await connection.send(chunk)
    }
    await connection.close()
}

// MARK: - Client side (a universal Network.framework loopback client over plain TCP)

private func startClient(port: UInt16) -> NWConnection? {
    guard let endpointPort = NWEndpoint.Port(rawValue: port) else { return nil }
    let connection = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
    connection.start(queue: DispatchQueue(label: "bench.transport.client"))
    return connection
}

private func clientSend(_ connection: NWConnection, _ bytes: [UInt8]) async {
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
        connection.send(
            content: Data(bytes),
            completion: .contentProcessed { _ in continuation.resume() })
    }
}

private func clientReceive(_ connection: NWConnection, maxLength: Int) async -> [UInt8]? {
    await withCheckedContinuation { (continuation: CheckedContinuation<[UInt8]?, Never>) in
        connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) {
            data, _, isComplete, _ in
            if let data, !data.isEmpty {
                continuation.resume(returning: [UInt8](data))
            } else if isComplete {
                continuation.resume(returning: nil)
            } else {
                continuation.resume(returning: [])
            }
        }
    }
}
