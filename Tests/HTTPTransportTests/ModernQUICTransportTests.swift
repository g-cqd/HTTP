//
//  ModernQUICTransportTests.swift
//  HTTPTransportTests
//
//  Loopback acceptance for the modern (macOS 26+) QUIC backbone, selected through
//  ``QUICTransportFactory`` on this OS: a real Network.framework QUIC client over the dev cert
//  exercises the typed-channel `NetworkConnection<QUIC>` transport end-to-end through the ``QUIC*``
//  abstraction — accept a connection, take its inbound stream, read the bytes with QUIC's FIN
//  (RFC 9000 §2), and echo them back. Skipped below macOS 26 (where the factory picks the legacy
//  backbone, covered by LegacyQUICTransportTests).
//

import Foundation
import HTTPCore
import Network
import Testing

@testable import HTTPTransport

@Suite("Modern QUIC transport — loopback")
struct ModernQUICTransportTests {
    @Test(
        "a QUIC stream round-trips through the modern backbone over loopback",
        .timeLimit(.minutes(1)))
    func loopbackEcho() async throws {
        guard #available(macOS 26, iOS 26, *) else {
            return
        }
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let transport = QUICTransportFactory.make(
            TransportConfiguration(
                host: "127.0.0.1",
                port: 0,
                backbone: .networkFramework,
                tls: tls
            )
        )
        #expect(transport is ModernQUICTransport)
        let connections = try await transport.start()
        let port = transport.boundPort

        let server = Task { await Self.echoServer(connections) }
        defer {
            server.cancel()
            Task { await transport.shutdown() }
        }

        let client = NWConnection(
            host: "127.0.0.1",
            port: NWEndpoint.Port(rawValue: port) ?? .any,
            using: Self.clientParameters()
        )
        defer { client.cancel() }
        try await ready(client)
        try await send([UInt8]("ping".utf8), on: client)
        let echoed = try await receive(from: client)
        #expect(echoed == [UInt8]("ping".utf8))
    }

    /// Echoes every byte of every inbound stream back to the peer, closing with FIN.
    private static func echoServer(_ connections: AsyncStream<any QUICConnection>) async {
        await withDiscardingTaskGroup { group in
            for await connection in connections {
                group.addTask {
                    await withDiscardingTaskGroup { streams in
                        for await stream in connection.inboundStreams() {
                            streams.addTask { await Self.echo(stream) }
                        }
                    }
                }
            }
        }
    }

    private static func echo(_ stream: any HTTPTransport.QUICStream) async {
        while let chunk = try? await stream.receive() {
            try? await stream.send(chunk.bytes, fin: chunk.fin)
            if chunk.fin { break }
        }
    }

    // MARK: Network.framework QUIC client

    private static func clientParameters() -> NWParameters {
        let options = NWProtocolQUIC.Options(alpn: ["h3"])
        sec_protocol_options_set_verify_block(
            options.securityProtocolOptions,
            { _, _, complete in complete(true) },
            DispatchQueue(label: "modern.quic.test.verify")
        )
        return NWParameters(quic: options)
    }

    private func ready(_ connection: NWConnection) async throws {
        let queue = DispatchQueue(label: "modern.quic.test.client")
        let resumed = ModernOnceLatch()
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                    case .ready where resumed.take():
                        continuation.resume()
                    case .failed(let error) where resumed.take():
                        continuation.resume(throwing: error)
                    default:
                        break
                }
            }
            connection.start(queue: queue)
        }
    }

    private func send(_ bytes: [UInt8], on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(
                content: Data(bytes),
                contentContext: .finalMessage,
                isComplete: true,
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    }
                    else {
                        continuation.resume()
                    }
                }
            )
        }
    }

    private func receive(from connection: NWConnection) async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_535) {
                data, _, _, error in
                if let error {
                    continuation.resume(throwing: error)
                }
                else {
                    continuation.resume(returning: [UInt8](data ?? Data()))
                }
            }
        }
    }
}
