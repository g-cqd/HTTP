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
        .networkFramework, .posixKqueue, .posixDispatch, .swiftSystem
    ]
    for backbone in socketBackbones {
        Benchmark("transport/\(backbone.rawValue)/echo") { benchmark async throws in
            // Every phase is watched: one that makes no progress for 15 s (a Network.framework callback that never
            // comes held the hosted macOS runner's job until its 25-minute timeout) fails the benchmark, naming the
            // phase, and one still stuck after that ends the process, rather than the job's clock.
            let watch = EchoWatch(name: "transport/\(backbone.rawValue)/echo")
            defer { watch.finish() }
            guard let (transport, boundPort) = makeSocketTransport(backbone) else {
                return
            }
            let stream: AsyncStream<any TransportConnection>
            do {
                watch.enter("start")
                stream = try await transport.start()
            }
            catch {
                return
            }
            let server = Task { await echoServer(stream) }
            let port = boundPort()
            guard port != 0, let client = startClient(port: port) else {
                await transport.shutdown()
                server.cancel()
                return
            }
            watch.onStall = { client.cancel() }

            benchmark.startMeasurement()
            for iteration in benchmark.scaledIterations {
                watch.enter("round trip", iteration)
                await clientSend(client, transportPayload)
                blackHole(await clientReceive(client, maxLength: 4_096))
                if let stalled = watch.stalled { throw EchoStall(name: watch.name, phase: stalled) }
            }
            benchmark.stopMeasurement()

            // The echo server ends before the transport does: with its event loop shut down, a POSIX backbone's
            // pending receive never completes, cancelled or not (posixKqueue and swiftSystem, measured), so
            // `server.value` waited without end.
            watch.enter("client cancel")
            client.cancel()
            watch.enter("echo server's end")
            server.cancel()
            _ = await server.value
            watch.enter("transport shutdown")
            await transport.shutdown()
        }
    }
}

// MARK: - Watchdog

struct EchoStall: Error, CustomStringConvertible {
    let name: String
    let phase: String
    var description: String { "\(name): no progress for \(EchoWatch.stallSeconds) s in \(phase)" }
}

/// The phase a socket benchmark is in, and a watchdog over it: no new phase for ``stallSeconds`` runs `onStall` (the
/// client's cancellation, which completes its pending send and receive) and marks the run stalled; still none
/// ``exitSeconds`` later, it reports the phase on standard error and ends the process.
final class EchoWatch: @unchecked Sendable {
    static let stallSeconds = 15
    static let exitSeconds = 45
    let name: String
    private let lock = NSLock()
    private var phase: StaticString = "setup"
    private var iteration = -1
    private var changed = ContinuousClock.now
    private var stalledPhase: String?
    private var done = false
    private var stallAction: (@Sendable () -> Void)?

    /// A timer on a dispatch queue, not a thread of its own: package-benchmark's malloc interposer traps when a
    /// thread it counts exits.
    private let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))

    init(name: String) {
        self.name = name
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            if tick() { timer.cancel() }
        }
        timer.resume()
    }

    var onStall: (@Sendable () -> Void)? {
        get { lock.withLock { stallAction } }
        set { lock.withLock { stallAction = newValue } }
    }

    var stalled: String? { lock.withLock { stalledPhase } }

    /// Allocates nothing: it runs once per measured round trip.
    func enter(_ next: StaticString, _ round: Int = -1) {
        lock.withLock { (phase, iteration, changed) = (next, round, .now) }
    }

    func finish() {
        lock.withLock { done = true }
        timer.cancel()
    }

    /// One look; true once the benchmark is done.
    private func tick() -> Bool {
        let (finished, current, quiet, action, already) = lock.withLock {
            (
                done, iteration < 0 ? "\(phase)" : "\(phase) \(iteration)",
                ContinuousClock.now - changed, stallAction, stalledPhase
            )
        }
        if finished { return true }
        if quiet > .seconds(Self.exitSeconds) {
            FileHandle.standardError.write(
                Data("\(name): still stuck in \(current) after \(quiet); exiting\n".utf8))
            exit(3)
        }
        if quiet > .seconds(Self.stallSeconds), already == nil {
            lock.withLock { stalledPhase = current }
            FileHandle.standardError.write(
                Data(
                    "\(name): no progress for \(quiet) in \(current); cancelling the client\n".utf8)
            )
            action?()
        }
        return false
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
        case .portableTLS, .posixEpoll, .unixDomainSocket, .fake:
            // Not exercised by the cleartext loopback echo: .portableTLS needs a TLS identity,
            // .posixEpoll is Linux-only, .unixDomainSocket binds a filesystem path (no TCP
            // port for the loopback client), and .fake binds no socket. Skipped here.
            return nil
    }
}

private func echoServer(_ stream: AsyncStream<any TransportConnection>) async {
    var iterator = stream.makeAsyncIterator()
    guard let connection = await iterator.next() else {
        return
    }
    // Until cancelled: an empty chunk is "no data yet", and after the client's cancellation the POSIX backbones
    // returned empty chunks without end, so a loop that only stopped at end-of-stream never let `server.value`
    // return (the benchmark then held the job until its timeout).
    while !Task.isCancelled {
        // `receive` returns `[UInt8]?`; `try?` flattens it, so nil means EOF or error → stop.
        guard let chunk = try? await connection.receive(maxLength: 65_536) else { break }
        if chunk.isEmpty {
            await Task.yield()  // no data yet, keep waiting
            continue
        }
        try? await connection.send(chunk)
    }
    await connection.close()
}

// MARK: - Client side (a universal Network.framework loopback client over plain TCP)

private func startClient(port: UInt16) -> NWConnection? {
    guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
        return nil
    }
    let connection = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
    connection.start(queue: DispatchQueue(label: "bench.transport.client"))
    return connection
}

private func clientSend(_ connection: NWConnection, _ bytes: [UInt8]) async {
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
        connection.send(
            content: Data(bytes),
            completion: .contentProcessed { _ in continuation.resume() }
        )
    }
}

private func clientReceive(_ connection: NWConnection, maxLength: Int) async -> [UInt8]? {
    await withCheckedContinuation { (continuation: CheckedContinuation<[UInt8]?, Never>) in
        connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) {
            data, _, isComplete, _ in
            if let data, !data.isEmpty {
                continuation.resume(returning: [UInt8](data))
            }
            else if isComplete {
                continuation.resume(returning: nil)
            }
            else {
                continuation.resume(returning: [])
            }
        }
    }
}
