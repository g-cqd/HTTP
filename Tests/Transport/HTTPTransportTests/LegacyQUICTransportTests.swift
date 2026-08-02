//
//  LegacyQUICTransportTests.swift
//  HTTPTransportTests
//
//  Loopback acceptance for the legacy QUIC backbone (the plan's top risk): a real Network.framework
//  QUIC client over the dev cert exercises ``LegacyQUICTransport`` end-to-end through the ``QUIC*``
//  abstraction — accept a connection, take its inbound stream, read the bytes with QUIC's FIN
//  (RFC 9000 §2), and echo them back. This validates the `NWConnectionGroup` accept model and the
//  FIN→`isComplete` mapping the HTTP/3 server relies on. (`curl --http3` is unavailable — the
//  SecureTransport curl ships no QUIC library — so a Network.framework client is the acceptance.)
//

import Foundation
import HTTPCore
import HTTPTestSupport
import Network
import Testing

@testable import HTTPTransport

@Suite("Legacy QUIC transport — loopback", .realNetwork)
struct LegacyQUICTransportTests {
    @Test(
        "a QUIC stream round-trips through the abstraction over loopback", .timeLimit(.minutes(1)))
    func loopbackEcho() async throws {
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let transport = LegacyQUICTransport(
            configuration: TransportConfiguration(
                host: "127.0.0.1",
                port: 0,
                backbone: .networkFramework,
                tls: tls
            )
        )
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
        try await ready(client, within: 10)
        defer { client.cancel() }
        try await send([UInt8]("ping".utf8), on: client)
        let echoed = try await receive(from: client)
        #expect(echoed == [UInt8]("ping".utf8))
    }

    @Test(
        "the legacy backbone offers h3 whatever ALPN list the shared TLS identity carries",
        .timeLimit(.minutes(1)),
        arguments: [["h2", "http/1.1"], ["h2"], [], ["h3"], ["h3", "h2"]])
    func http3IsOfferedRegardlessOfTheTCPProtocolList(_ configured: [String]) async throws {
        // The same defect as the modern backbone's, measured the same way: both derive the QUIC ALPN
        // from ``TransportTLS/applicationProtocols``, whose documented default is the TCP set
        // `["h2", "http/1.1"]`, so neither ever offered `h3` (RFC 9114 §3.1) to a client that did not
        // already agree with us. RFC 9001 §8.1 requires the connection to close when no application
        // protocol is negotiated, which is why h3spec reports 15/15 identically on BOTH backbones —
        // this was never a modern-vs-legacy difference.
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: configured)
        let transport = LegacyQUICTransport(
            configuration: TransportConfiguration(
                host: "127.0.0.1",
                port: 0,
                backbone: .networkFramework,
                tls: tls
            )
        )
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
        try await ready(client, within: 10)
        #expect(Self.negotiatedALPN(of: client) == "h3")
    }

    /// The ALPN identifier a ready QUIC `connection` negotiated (RFC 7301), or `nil`.
    private static func negotiatedALPN(of connection: NWConnection) -> String? {
        let metadata = connection.metadata(definition: NWProtocolQUIC.definition)
        return (metadata as? NWProtocolQUIC.Metadata)?.negotiatedALPN
    }

    @Test(
        "the legacy backbone binds the configured host and port, and reports what it bound",
        .timeLimit(.minutes(1)))
    func configuredEndpointIsHonored() async throws {
        // This backbone always applied the configured port, but built its `NWParameters` without a
        // required local endpoint — so the configured *host* was ignored and a loopback-configured h3
        // listener bound every interface (the other half of audit F-04/F-05).
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let transport = LegacyQUICTransport(
            configuration: TransportConfiguration(
                host: "127.0.0.1",
                port: 0,
                backbone: .networkFramework,
                tls: tls
            )
        )
        let connections = try await transport.start()
        #expect(transport.boundPort != 0)
        let bound = try #require(transport.boundEndpoint)
        #expect(bound.address == "127.0.0.1")
        #expect(bound.port == transport.boundPort)
        withExtendedLifetime(connections) {
            // Held so the listener is not torn down before the assertions above.
        }
        await transport.shutdown()
    }

    @Test(
        "an unbindable configured host fails closed on the legacy backbone",
        .timeLimit(.minutes(1)), arguments: ["192.0.2.1", "legacy-quic-bind.invalid"])
    func unbindableHostFailsClosed(_ host: String) async throws {
        // RFC 5737 TEST-NET-1 and RFC 2606 §2's `.invalid` are both unbindable, so `start()` must
        // throw rather than silently widen the listener to another interface (CWE-668).
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let transport = LegacyQUICTransport(
            configuration: TransportConfiguration(
                host: host,
                port: 0,
                backbone: .networkFramework,
                tls: tls
            )
        )
        await #expect(throws: TransportError.self) {
            _ = try await transport.start()
            await transport.shutdown()
        }
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
        // The dev identity is self-signed: accept it for this loopback test only.
        sec_protocol_options_set_verify_block(
            options.securityProtocolOptions,
            { _, _, complete in complete(true) },
            DispatchQueue(label: "quic.test.verify")
        )
        return NWParameters(quic: options)
    }

    /// Waits up to `seconds` for `connection` to complete its QUIC handshake.
    ///
    /// The deadline is load-bearing, not defensive: when the server offers no ALPN the client can
    /// accept, Apple's QUIC stack reports `.waiting(POSIXErrorCode(57))` and retries forever rather
    /// than reaching `.failed`, so a bare `.ready`/`.failed` wait parks until the suite's time limit
    /// and names nothing. The deadline turns that into a diagnosis.
    private func ready(_ connection: NWConnection, within seconds: Int) async throws {
        let queue = DispatchQueue(label: "quic.test.client")
        let resumed = OnceLatch()
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
            queue.asyncAfter(deadline: .now() + .seconds(seconds)) {
                guard resumed.take() else {
                    return
                }
                continuation.resume(
                    throwing: TransportError.tlsConfigurationFailed(
                        "QUIC handshake did not complete in \(seconds)s — no ALPN overlap?"
                    )
                )
            }
            connection.start(queue: queue)
        }
    }

    private func send(_ bytes: [UInt8], on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(
                content: Data(bytes),
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
