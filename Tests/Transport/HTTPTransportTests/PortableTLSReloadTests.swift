//
//  PortableTLSReloadTests.swift
//  HTTPTransportTests
//
//  Hot certificate reload (G4b parity) on the portable TLS backbone (ADR 0004): `reload(tls:)` swaps
//  the shared `SSL_CTX` so new handshakes use the new identity — a `Mutex`-guarded pointer swap with no
//  port rebind (unlike the Network backbone's restart-based reload). A libssl client reads back which
//  server leaf it was handed before and after the swap.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — runs only in the opt-in portable build (`HTTP_PORTABLE_TLS`).
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    internal import Darwin
    internal import Dispatch
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS (vendored BoringSSL) — hot certificate reload (G4b, ADR 0004)")
    struct PortableTLSReloadTests {
        @Test(
            "reload swaps the served certificate for new connections",
            .timeLimit(.minutes(1)))
        func reloadSwapsServedCertificate() async throws {
            let identityA = try DevTLSIdentity.selfSigned(commonName: "reload-cert-a")
            let transport = PortableTLSTransport(
                configuration: TransportConfiguration(
                    port: 0, backbone: .portableTLS, tls: identityA
                )
            )
            let connections = try await transport.start()
            let port = transport.boundPort
            #expect(port != 0)

            let server = Task { await Self.drain(connections) }
            defer {
                server.cancel()
                Task { await transport.shutdown() }
            }

            // Before the reload, a new connection is served certificate A.
            #expect(await Self.serverLeafCN(port: port) == "reload-cert-a")

            let identityB = try DevTLSIdentity.selfSigned(commonName: "reload-cert-b")
            try await transport.reload(tls: identityB)

            // After the reload, a new connection is served certificate B (no port rebind).
            #expect(await Self.serverLeafCN(port: port) == "reload-cert-b")

            await transport.shutdown()
        }

        @Test("reload before start fails closed (the transport is not accepting)")
        func reloadBeforeStartThrows() async throws {
            let identity = try DevTLSIdentity.selfSigned()
            let transport = PortableTLSTransport(
                configuration: TransportConfiguration(
                    port: 0, backbone: .portableTLS, tls: identity
                )
            )
            await #expect(throws: TransportError.closed) {
                try await transport.reload(tls: identity)
            }
        }

        // MARK: - Helpers

        private static func drain(_ connections: AsyncStream<any TransportConnection>) async {
            for await connection in connections {
                await connection.close()
            }
        }

        /// The Common Name of the server leaf a fresh libssl client is handed on `port`.
        private static func serverLeafCN(port: UInt16) async -> String? {
            await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
                DispatchQueue.global()
                    .async {
                        let leafCN = handshakeLeafCN(port: port)
                        continuation.resume(returning: leafCN)
                    }
            }
        }

        private static func handshakeLeafCN(port: UInt16) -> String? {
            let descriptor = CHTTPBoringSSLShims_connect_loopback(port)
            guard descriptor >= 0,
                let context = CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_client_method())
            else {
                return nil
            }
            defer { CHTTPBoringSSL_SSL_CTX_free(context) }
            CHTTPBoringSSL_SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
            guard let ssl = CHTTPBoringSSL_SSL_new(context) else {
                _ = Darwin.close(descriptor)
                return nil
            }
            defer {
                CHTTPBoringSSL_SSL_free(ssl)
                _ = Darwin.close(descriptor)
            }
            CHTTPBoringSSL_SSL_set_fd(ssl, descriptor)
            guard CHTTPBoringSSL_SSL_connect(ssl) == 1 else {
                return nil
            }
            return OpenSSLTLS.peerSubject(of: ssl)
        }
    }

#endif
