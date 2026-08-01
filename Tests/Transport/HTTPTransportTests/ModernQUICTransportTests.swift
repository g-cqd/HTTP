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

internal import Darwin

import Foundation
import HTTPCore
import HTTPTestSupport
import Network
import Testing

@testable import HTTPTransport

@Suite("Modern QUIC transport — loopback", .realNetwork)
struct ModernQUICTransportTests {
    @Test(
        "the modern backbone binds the configured nonzero port",
        .timeLimit(.minutes(1)))
    func configuredPort() async throws {
        guard #available(macOS 26, iOS 26, *) else {
            return
        }
        let requestedPort = try Self.unusedUDPPort()
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let transport = ModernQUICTransport(
            configuration: TransportConfiguration(
                host: "127.0.0.1",
                port: requestedPort,
                backbone: .networkFramework,
                tls: tls
            )
        )
        _ = try await transport.start()
        defer { Task { await transport.shutdown() } }

        #expect(
            transport.boundPort == requestedPort,
            "configured UDP port \(requestedPort), but modern QUIC bound \(transport.boundPort)"
        )
    }

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

    /// Lets the kernel choose an unused loopback UDP port, then releases it for the listener under test.
    private static func unusedUDPPort() throws -> UInt16 {
        let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard descriptor >= 0 else {
            throw TransportError.bindFailed("socket() errno \(errno)")
        }
        defer { close(descriptor) }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let didBind = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        guard didBind else {
            throw TransportError.bindFailed("bind() errno \(errno)")
        }

        var bound = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let didReadPort = withUnsafeMutablePointer(to: &bound) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &length) == 0
            }
        }
        guard didReadPort else {
            throw TransportError.bindFailed("getsockname() errno \(errno)")
        }
        return UInt16(bigEndian: bound.sin_port)
    }
}
