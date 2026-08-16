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
        let connections = try await transport.start()

        #expect(
            transport.boundPort == requestedPort,
            "configured UDP port \(requestedPort), but modern QUIC bound \(transport.boundPort)"
        )
        // The endpoint an operator (and `Alt-Svc`, RFC 7838) should see: resolved interface + real port.
        let bound = try #require(transport.boundEndpoint)
        #expect(bound.address == "127.0.0.1")
        #expect(bound.port == requestedPort)
        #expect(bound.description == "127.0.0.1:\(requestedPort)")
        withExtendedLifetime(connections) {
            // Held so the listener is not torn down before the assertions above.
        }
        await transport.shutdown()
    }

    @Test(
        "port 0 stays an explicit ephemeral request on the modern backbone",
        .timeLimit(.minutes(1)))
    func ephemeralPortIsStillEphemeral() async throws {
        guard #available(macOS 26, iOS 26, *) else {
            return
        }
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let transport = ModernQUICTransport(
            configuration: TransportConfiguration(
                host: "127.0.0.1",
                port: 0,
                backbone: .networkFramework,
                tls: tls
            )
        )
        let connections = try await transport.start()
        #expect(transport.boundPort != 0, "port 0 must realize an OS-chosen port, not stay 0")
        #expect(transport.boundEndpoint?.port == transport.boundPort)
        withExtendedLifetime(connections) {
            // Held so the listener is not torn down before the assertions above.
        }
        await transport.shutdown()
    }

    @Test(
        "an unbindable configured host fails closed instead of binding somewhere else",
        .timeLimit(.minutes(1)), arguments: ["192.0.2.1", "quic-bind-target.invalid"])
    func unbindableHostFailsClosed(_ host: String) async throws {
        guard #available(macOS 26, iOS 26, *) else {
            return
        }
        // RFC 5737 TEST-NET-1 is assigned to no host and RFC 2606 §2's `.invalid` resolves nowhere, so
        // a QUIC listener configured for either must throw rather than land on another interface.
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let transport = ModernQUICTransport(
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

    @Test(
        "a second QUIC listener on the same UDP port fails closed",
        .timeLimit(.minutes(1)))
    func portConflictFailsClosed() async throws {
        guard #available(macOS 26, iOS 26, *) else {
            return
        }
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let holder = ModernQUICTransport(
            configuration: TransportConfiguration(
                host: "127.0.0.1",
                port: 0,
                backbone: .networkFramework,
                tls: tls
            )
        )
        let held = try await holder.start()
        let port = holder.boundPort
        #expect(port != 0)

        let clashing = ModernQUICTransport(
            configuration: TransportConfiguration(
                host: "127.0.0.1",
                port: port,
                backbone: .networkFramework,
                tls: tls
            )
        )
        await #expect(throws: TransportError.self) {
            let stream = try await clashing.start()
            withExtendedLifetime(stream) {
                // Held so a successful bind is observable rather than instantly undone.
            }
            await clashing.shutdown()
        }
        withExtendedLifetime(held) {
            // The holder must keep the port for the whole clash attempt.
        }
        await holder.shutdown()
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
        try await ready(client, within: 10)
        try await send([UInt8]("ping".utf8), on: client)
        let echoed = try await receive(from: client)
        #expect(echoed == [UInt8]("ping".utf8))
    }

    @Test(
        "the modern backbone offers h3 whatever ALPN list the shared TLS identity carries",
        .timeLimit(.minutes(1)),
        arguments: [["h2", "http/1.1"], ["h2"], [], ["h3"], ["h3", "h2"]])
    func http3IsOfferedRegardlessOfTheTCPProtocolList(_ configured: [String]) async throws {
        guard #available(macOS 26, iOS 26, *) else {
            return
        }
        // ``TransportTLS/applicationProtocols`` is ONE list shared by the TCP TLS listener and the
        // QUIC listener, and its documented default is the TCP set `["h2", "http/1.1"]`. Feeding that
        // set to QUIC advertised identifiers that are defined for HTTP over TCP (RFC 9113 §3.3,
        // RFC 7301) and never `h3` (RFC 9114 §3.1), so a third-party client offering only `h3` shared
        // no protocol with us. RFC 9001 §8.1 makes that fatal: "endpoints MUST immediately close a
        // connection … with a no_application_protocol TLS alert … if an application protocol is not
        // negotiated". Every non-Apple client (curl --http3-only, h3spec) hit exactly this; the
        // in-repo tests did not, because they all hand-configure `["h3"]` on BOTH ends.
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: configured)
        let transport = ModernQUICTransport(
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
        "close(errorCode:) closes promptly; the code itself is pinned platform-discarded",
        .timeLimit(.minutes(1)),
        arguments: [
            UInt64(0x010A),  // H3_MISSING_SETTINGS (RFC 9114 §8.1)
            UInt64(0x0105)  // H3_FRAME_UNEXPECTED (RFC 9114 §8.1)
        ])
    func closeCarriesTheApplicationErrorCode(_ code: UInt64) async throws {
        guard #available(macOS 26, iOS 26, *) else {
            return
        }
        // RFC 9114 §8.1 mandates *specific* application error codes, delivered in the frame type 0x1d
        // CONNECTION_CLOSE (RFC 9000 §10.2 / §19.19). The engine selects the code and the dispatcher
        // forwards it to `close(errorCode:)` — but Network.framework's structured teardown emits the
        // frame with a hardwired code 0, whatever `applicationError` holds (the dominant cause of the
        // h3spec "HTTP/3 servers" failures; the experiment matrix is in CONFORMANCE.md).
        //
        // Two hard guarantees, and one pinned premise:
        //  1. HARD: the peer observes the close promptly — a close that stops closing (the previous
        //     record's symptom) or crashes (`nw_quic_set_application_error` segfaults on a nil reason;
        //     its true cause) fails this test outright.
        //  2. PINNED (`withKnownIssue`): the peer reads back the code `close(errorCode:)` was asked
        //     for. Today Apple's stack discards it; the day an SDK starts honoring the recorded
        //     `applicationError`, the known issue stops reproducing, this test flags it, and the
        //     platform-blocked rows in CONFORMANCE.md can be lifted.
        // The probe reproduces the engine's shape at a §8.1 violation: one inbound stream is open and
        // mid-read when the close is issued.
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let transport = ModernQUICTransport(
            configuration: TransportConfiguration(
                host: "127.0.0.1",
                port: 0,
                backbone: .networkFramework,
                tls: tls
            )
        )
        let connections = try await transport.start()
        let port = transport.boundPort

        let server = Task { await Self.closeFirstConnection(connections, errorCode: code) }
        defer {
            server.cancel()
            Task { await transport.shutdown() }
        }

        let probe = QUICApplicationCloseProbe(port: port)
        defer { probe.cancel() }
        try await probe.ready(within: 10)
        try await probe.send([0x00])
        // Hard: the close must arrive inside the deadline (a hang throws and fails the test).
        let observed = try await probe.observedCloseCode(within: 15)
        withKnownIssue(
            "Network.framework discards the QUIC application close code (see CONFORMANCE.md)"
        ) {
            #expect(
                observed == code,
                "closed with application error \(String(observed, radix: 16)), asked for \(String(code, radix: 16))"
            )
        }
    }

    /// Accepts one connection, parks a read on its first inbound stream (the HTTP/3 engine's shape at
    /// a §8.1 violation), then closes the whole connection with `errorCode`.
    private static func closeFirstConnection(
        _ connections: AsyncStream<any QUICConnection>,
        errorCode: UInt64
    ) async {
        for await connection in connections {
            var streams = connection.inboundStreams().makeAsyncIterator()
            guard let stream = await streams.next() else {
                break
            }
            _ = try? await stream.receive()
            let parked = Task { _ = try? await stream.receive() }
            await connection.close(errorCode: errorCode)
            parked.cancel()
            break
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
        sec_protocol_options_set_verify_block(
            options.securityProtocolOptions,
            { _, _, complete in complete(true) },
            DispatchQueue(label: "modern.quic.test.verify")
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
