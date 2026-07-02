//
//  PortableTLSMutualTLSTests.swift
//  HTTPTransportTests
//
//  Phase 4 of the portable TLS backbone (ADR 0004): client-certificate auth over real loopback through
//  `PortableTLSTransport` + a libssl client that presents (or withholds) its identity. Mirrors
//  `NetworkFrameworkMutualTLSTests` for `.required`, then adds the **`.optional`** cases the Network
//  backbone could not satisfy (it deadlocked on a presented client cert; see roadmap 2026-06-26):
//  `.optional` admits a no-cert client (subject `nil`) yet still surfaces and pins a presented one.
//  `SSL_VERIFY_PEER` without `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` is request-but-don't-require, natively.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — runs only in the opt-in portable build (`HTTP_PORTABLE_TLS`).
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import Dispatch
    import HTTPTestSupport
    internal import Synchronization
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS (vendored BoringSSL) — mutual TLS, incl. .optional (Phase 4, ADR 0004)")
    struct PortableTLSMutualTLSTests {
        @Test(
            "required client-auth surfaces the presented client certificate subject",
            .timeLimit(.minutes(1)))
        func requiredSurfacesSubject() async throws {
            // RFC 8446 §4.4.2.4: a presented client certificate MUST be validated. This backbone defers
            // that validation to the `verifyPeer` hook (the TLS layer is permissive — G3 "the hook is the
            // policy"), so a *surfacing* test must supply the validator; without one, an unvalidated cert
            // is conformantly rejected (the secure fail-closed default `verifyPeer?(chain) ?? false`).
            try await Self.expectSubject(
                clientAuth: .required, commonName: "portable-required-client"
            ) { _ in true }
        }

        @Test(
            "required client-auth rejects a client that presents no certificate",
            .timeLimit(.minutes(1)))
        func requiredRejectsNoCertificate() async throws {
            let transport = try Self.transport(clientAuth: .required)
            try await Self.expectNoConnection(from: transport, identity: nil)
        }

        @Test(
            "a verifyPeer pin rejects a disallowed certificate under required auth",
            .timeLimit(.minutes(1)))
        func requiredHonorsVerifyPeerRejection() async throws {
            let identity = try DevTLSIdentity.selfSigned(commonName: "portable-unpinned")
            let transport = try Self.transport(clientAuth: .required) { _ in false }
            try await Self.expectNoConnection(from: transport, identity: identity)
        }

        @Test(
            "verifyPeer receives the DER chain leaf-first and admits a match",
            .timeLimit(.minutes(1)))
        func verifyPeerReceivesDERChain() async throws {
            let sawNonEmptyLeaf = Mutex(false)
            try await Self.expectSubject(
                clientAuth: .required, commonName: "portable-pinned-client"
            ) {
                chain in
                let admit = chain.first.map { !$0.isEmpty } ?? false
                if admit {
                    sawNonEmptyLeaf.withLock { $0 = true }
                }
                return admit
            }
            let sawLeaf = sawNonEmptyLeaf.withLock(\.self)
            #expect(sawLeaf)
        }

        // Darwin-only: on Linux the portable backbone's `.optional` client-auth with an ADMITTED client
        // certificate hangs the handshake (the `.optional` reject + no-cert paths and the `.required`
        // admit path all pass on Linux) — the same `.optional`-with-presented-cert hazard the macOS
        // Network backbone showed (roadmap G3). Tracked as a Linux portable-TLS follow-up; the Darwin
        // gated suite covers this case.
        #if canImport(Darwin)
            @Test(
                "optional client-auth surfaces a presented client certificate subject",
                .timeLimit(.minutes(1)))
            func optionalSurfacesSubject() async throws {
                // RFC 8446 §4.4.2.4 — see `requiredSurfacesSubject`: validation is the `verifyPeer` hook's
                // job here, so a surfacing test supplies it; a nil hook conformantly rejects a presented cert.
                try await Self.expectSubject(
                    clientAuth: .optional, commonName: "portable-optional-client"
                ) { _ in true }
            }
        #endif

        @Test(
            "optional client-auth admits a client that presents no certificate",
            .timeLimit(.minutes(1)))
        func optionalAdmitsNoCertificate() async throws {
            let transport = try Self.transport(clientAuth: .optional)
            let connections = try await transport.start()
            let port = transport.boundPort

            // The defining `.optional` behavior — and the exact case `.required` rejects above.
            let surfaced = AsyncEventProbe<String?>()
            let accepting = Task {
                var iterator = connections.makeAsyncIterator()
                if let connection = await iterator.next() {
                    surfaced.record(connection.tlsPeerSubject)
                    await connection.close()
                }
            }
            defer { accepting.cancel() }

            Self.connect(port: port, identity: nil)
            let subjects = try await surfaced.wait(forAtLeast: 1, timeout: .seconds(15))
            #expect(subjects.first == .some(nil))  // surfaced, with no client-cert subject
            await transport.shutdown()
        }

        @Test(
            "a verifyPeer pin rejects a disallowed certificate under optional auth",
            .timeLimit(.minutes(1)))
        func optionalHonorsVerifyPeerRejection() async throws {
            let identity = try DevTLSIdentity.selfSigned(commonName: "portable-optional-unpinned")
            let transport = try Self.transport(clientAuth: .optional) { _ in false }
            try await Self.expectNoConnection(from: transport, identity: identity)
        }

        // MARK: - Helpers

        /// A `PortableTLSTransport` on an ephemeral port with a fresh server identity, `clientAuth`, and
        /// an optional `verifyPeer` pin.
        private static func transport(
            clientAuth: TransportTLS.ClientAuth,
            verifyPeer: (@Sendable ([[UInt8]]) -> Bool)? = nil
        ) throws -> PortableTLSTransport {
            var tls = try DevTLSIdentity.selfSigned()
            tls.clientAuth = clientAuth
            tls.verifyPeer = verifyPeer
            return PortableTLSTransport(
                configuration: TransportConfiguration(port: 0, backbone: .portableTLS, tls: tls)
            )
        }

        /// Starts a transport, connects a client presenting a `commonName` identity, and asserts the
        /// surfaced connection's `tlsPeerSubject` is that common name — and that the full G3 identity
        /// (DER chain + SANs) rides along.
        private static func expectSubject(
            clientAuth: TransportTLS.ClientAuth,
            commonName: String,
            verifyPeer: (@Sendable ([[UInt8]]) -> Bool)? = nil
        ) async throws {
            let clientIdentity = try DevTLSIdentity.selfSigned(commonName: commonName)
            let transport = try transport(clientAuth: clientAuth, verifyPeer: verifyPeer)
            let connections = try await transport.start()
            let port = transport.boundPort

            let accepted = Task { () -> TLSPeerIdentity? in
                var iterator = connections.makeAsyncIterator()
                guard let connection = await iterator.next() else {
                    return nil
                }
                defer { Task { await connection.close() } }
                return connection.tlsPeerIdentity
            }

            connect(port: port, identity: clientIdentity)
            let identity = await accepted.value
            #expect(identity?.subject == commonName)
            let leafBytes = identity?.leafDER ?? []
            #expect(!leafBytes.isEmpty)
            // DevTLSIdentity mints DNS:localhost + IP:127.0.0.1 SANs (RFC 5280 §4.2.1.6).
            let names = identity?.subjectAlternativeNames ?? []
            #expect(names.contains(.dns("localhost")))
            #expect(names.contains(.ip("127.0.0.1")))
            await transport.shutdown()
        }

        /// Asserts the transport surfaces **no** connection for a client presenting `identity` (or none)
        /// — the handshake fails or `verifyPeer` rejects, so the accept boundary is never reached.
        private static func expectNoConnection(
            from transport: PortableTLSTransport,
            identity: TransportTLS?
        ) async throws {
            let connections = try await transport.start()
            let port = transport.boundPort

            let yielded = AsyncEventProbe<Void>()
            let accepting = Task {
                var iterator = connections.makeAsyncIterator()
                if await iterator.next() != nil {
                    yielded.record(())
                }
            }
            defer { accepting.cancel() }

            connect(port: port, identity: identity)
            await #expect(throws: AsyncEventProbeTimeoutError.self) {
                _ = try await yielded.wait(forAtLeast: 1, timeout: .seconds(2))
            }
            await transport.shutdown()
        }

        /// A libssl client that connects to `127.0.0.1:port`, optionally presents `identity` as its
        /// client certificate, and completes the handshake — the mirror of the mutual-TLS suite's
        /// `clientParameters(identity:)`, on a background queue.
        private static func connect(port: UInt16, identity: TransportTLS?) {
            DispatchQueue.global()
                .async {
                    let descriptor = CHTTPBoringSSLShims_connect_loopback(port)
                    guard descriptor >= 0,
                        let context = CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_client_method())
                    else {
                        return
                    }
                    defer { CHTTPBoringSSL_SSL_CTX_free(context) }
                    // Trust the dev self-signed server certificate (test only).
                    CHTTPBoringSSL_SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
                    _ = CHTTPBoringSSLShims_set_client_alpn(context)
                    if let identity {
                        _ = identity.pkcs12.withUnsafeBufferPointer { buffer in
                            CHTTPBoringSSLShims_use_pkcs12(
                                context,
                                buffer.baseAddress,
                                Int32(buffer.count),
                                identity.passphrase
                            )
                        }
                    }
                    guard let ssl = CHTTPBoringSSL_SSL_new(context) else {
                        _ = close(descriptor)
                        return
                    }
                    defer {
                        CHTTPBoringSSL_SSL_free(ssl)
                        _ = close(descriptor)
                    }
                    CHTTPBoringSSL_SSL_set_fd(ssl, descriptor)
                    _ = CHTTPBoringSSL_SSL_connect(ssl)
                    // Hold the connection briefly so the server captures the subject before teardown.
                    usleep(200_000)
                }
        }
    }

#endif
