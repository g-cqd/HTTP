//
//  InteropServer.swift
//  HTTPTransportTests
//
//  The transport-level echo server every interop scenario dials: HTTP-shaped requests get
//  one canned response (curl's scenario), everything else is echoed back `srv:`-prefixed
//  (`s_client`'s scenarios — the prefix defeats the PTY's local echo). Captures per-
//  connection ALPN and peer subject so scenarios can assert the server-side view too.
//

#if canImport(CHTTPBoringSSLShims) || HTTP_PORTABLE_TLS_SWIFT

    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import Foundation
    internal import Synchronization

    @testable import HTTPTransport

    /// A transport-level echo server over the portable TLS backbone.
    ///
    /// HTTP-shaped requests get one canned response (curl's scenario); everything else is
    /// echoed back `srv:`-prefixed (`s_client`'s scenarios). Captures the per-connection
    /// ALPN and peer subject so the scenarios can assert the server-side view too.
    final class InteropServer: @unchecked Sendable {
        private let transport: PortableTLSTransport
        private var accepting: Task<Void, Never>?
        private let negotiated = Mutex<[String?]>([])
        private let peerSubjects = Mutex<[String?]>([])

        /// The bound port.
        let port: UInt16

        init(tls: TransportTLS) async throws {
            transport = PortableTLSTransport(
                configuration: TransportConfiguration(
                    port: 0, backbone: .portableTLS, tls: tls
                )
            )
            let connections = try await transport.start()
            port = transport.boundPort
            // `Mutex` is ~Copyable — the accept task reaches the capture lists through
            // `self` (weakly: `tearDown()` cancels it, and the loop ends with the stream).
            accepting = Task { [weak self] in
                for await connection in connections {
                    self?.negotiated
                        .withLock { $0.append(connection.negotiatedApplicationProtocol) }
                    self?.peerSubjects.withLock { $0.append(connection.tlsPeerSubject) }
                    Task { await Self.serve(connection) }
                }
            }
        }

        deinit {
            // `tearDown()` is the tests' teardown (a `defer` at every use site).
        }

        /// Whether any served connection negotiated `alpn`.
        func sawNegotiatedProtocol(_ alpn: String) async -> Bool {
            negotiated.withLock { $0.contains(alpn) }
        }

        /// Whether any served connection presented a client certificate with `subject`.
        func sawPeerSubject(_ subject: String) async -> Bool {
            peerSubjects.withLock { $0.contains(subject) }
        }

        /// How many connections completed a handshake and were surfaced — the reject arm's
        /// oracle: a refused handshake must never surface (§4.4.2.4 fail-closed).
        func surfacedConnections() -> Int {
            negotiated.withLock(\.count)
        }

        /// Hot-reloads the listener's identity (the matrix's reload scenario).
        func reload(tls: TransportTLS) async throws {
            try await transport.reload(tls: tls)
        }

        /// Stops accepting and shuts the listener down.
        func tearDown() {
            accepting?.cancel()
            let transport = transport
            Task { await transport.shutdown() }
        }

        /// The per-connection loop: canned HTTP answer or raw echo, until end of stream.
        private static func serve(_ connection: any TransportConnection) async {
            let response = Array(
                """
                HTTP/1.1 200 OK\r
                Content-Length: 19\r
                Connection: close\r
                \r
                portable-interop-ok
                """
                .utf8
            )
            while true {
                let received: [UInt8]?
                do {
                    received = try await connection.receive(maxLength: 65_536)
                }
                catch {
                    received = nil
                }
                guard let received else {
                    break
                }
                if received.starts(with: Array("GET ".utf8)) {
                    try? await connection.send(response)
                }
                else {
                    // `srv:`-prefixed, so a PTY's local echo of the probe can never satisfy
                    // an assertion that the SERVER answered.
                    try? await connection.send(Array("srv:".utf8) + received)
                }
            }
            await connection.close()
        }
    }

#endif
