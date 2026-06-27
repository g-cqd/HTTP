//
//  PortableTLSSNITests.swift
//  HTTPTransportTests
//
//  Phase 5 of the portable TLS backbone (ADR 0004): SNI multi-cert selection (RFC 6066 §3) — the other
//  W2/G4 deferral. The server holds a default identity plus a `server_name` → identity map; a libssl
//  client sends an SNI host name and reads back **which** server leaf it was handed. Network.framework
//  exposes no server-side server-name callback (legacy or modern); OpenSSL/BoringSSL do
//  (`CHTTPBoringSSL_SSL_CTX_set_tlsext_servername_callback` + per-name `SSL_CTX`).
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

    @Suite("Portable TLS (vendored BoringSSL) — SNI multi-cert (Phase 5, ADR 0004)")
    struct PortableTLSSNITests {
        @Test(
            "the handshake's server_name selects the matching certificate, else the default",
            .timeLimit(.minutes(1)))
        func sniSelectsPerNameCertificate() async throws {
            let transport = try Self.sniTransport()
            let connections = try await transport.start()
            let port = transport.boundPort
            #expect(port != 0)

            // Drain the accepted connections so each handshake completes and the connection is closed.
            let server = Task { await Self.drain(connections) }
            defer {
                server.cancel()
                Task { await transport.shutdown() }
            }

            // The server leaf each SNI name resolves to (its CN equals the name; the default is the
            // dev `localhost` identity).
            #expect(await Self.serverLeafCN(port: port, serverName: "alpha.test") == "alpha.test")
            #expect(await Self.serverLeafCN(port: port, serverName: "beta.test") == "beta.test")
            #expect(
                await Self.serverLeafCN(port: port, serverName: "unmatched.test") == "localhost")
            #expect(await Self.serverLeafCN(port: port, serverName: nil) == "localhost")

            await transport.shutdown()
        }

        // MARK: - Helpers

        /// A transport whose default identity is the dev `localhost` cert, with two SNI identities whose
        /// CNs equal their server-names.
        private static func sniTransport() throws -> PortableTLSTransport {
            var tls = try DevTLSIdentity.selfSigned()  // default identity, CN=localhost
            tls.sniIdentities = [
                "alpha.test": try sniIdentity(commonName: "alpha.test"),
                "beta.test": try sniIdentity(commonName: "beta.test")
            ]
            return PortableTLSTransport(
                configuration: TransportConfiguration(port: 0, backbone: .portableTLS, tls: tls)
            )
        }

        /// A fresh SNI identity whose certificate Common Name is `commonName`.
        private static func sniIdentity(commonName: String) throws -> TransportTLS.SNIIdentity {
            let identity = try DevTLSIdentity.selfSigned(commonName: commonName)
            return TransportTLS.SNIIdentity(
                pkcs12: identity.pkcs12, passphrase: identity.passphrase
            )
        }

        /// Consumes and closes every connection the transport surfaces (so handshakes complete).
        private static func drain(_ connections: AsyncStream<any TransportConnection>) async {
            for await connection in connections {
                await connection.close()
            }
        }

        /// Connects a libssl client with `serverName` (or none), completes the handshake, and returns
        /// the Common Name of the server leaf certificate it was handed.
        private static func serverLeafCN(port: UInt16, serverName: String?) async -> String? {
            await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
                DispatchQueue.global()
                    .async {
                        let leafCN = handshakeLeafCN(port: port, serverName: serverName)
                        continuation.resume(returning: leafCN)
                    }
            }
        }

        private static func handshakeLeafCN(port: UInt16, serverName: String?) -> String? {
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
            if let serverName {
                serverName.withCString { CHTTPBoringSSLShims_set_sni(ssl, $0) }
            }
            guard CHTTPBoringSSL_SSL_connect(ssl) == 1 else {
                return nil
            }
            return OpenSSLTLS.peerSubject(of: ssl)  // the server leaf the SNI callback selected
        }
    }

#endif
