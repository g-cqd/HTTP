//
//  NetworkFrameworkMutualTLSTests.swift
//  HTTPTransportTests
//
//  Mutual-TLS (G3) coverage for the Network.framework backbone over real loopback handshakes: a
//  `.required` client-auth listener surfaces the presented client certificate's subject as
//  `tlsPeerSubject`, refuses a connection that presents no client certificate, and honors a
//  `verifyPeer` pin over the DER chain — accepting a matching chain and failing the handshake on a
//  rejection. The test client presents its identity through `sec_protocol_options_set_local_identity`,
//  the mirror of the server's local identity, and is minted with `DevTLSIdentity.selfSigned`.
//

internal import Dispatch
import HTTPTestSupport
internal import Network
internal import Security
internal import Synchronization
import Testing

@testable import HTTPTransport

@Suite("Network.framework backbone — mutual TLS (client certificates)")
struct NetworkFrameworkMutualTLSTests {
    @Test(
        "required client-auth surfaces the presented client certificate subject",
        .timeLimit(.minutes(1)))
    func requiredClientAuthSurfacesSubject() async throws {
        let clientCN = "mTLS-test-client"
        let clientIdentity = try Self.clientIdentity(commonName: clientCN)
        // `.required` now demands an explicit verify hook (audit F4); accept any presented cert here so
        // this test still exercises subject surfacing.
        let transport = try Self.mutualTLSTransport { _ in true }
        let connections = try await transport.start()
        let port = try #require(NWEndpoint.Port(rawValue: transport.boundPort))

        // The accepted connection is surfaced only after `.ready`, so its peer identity is settled.
        let accepted = Task { () -> TLSPeerIdentity? in
            var iterator = connections.makeAsyncIterator()
            guard let connection = await iterator.next() else {
                return nil
            }
            defer { Task { await connection.close() } }
            return connection.tlsPeerIdentity
        }

        let client = NWConnection(
            host: "127.0.0.1", port: port, using: Self.clientParameters(identity: clientIdentity)
        )
        client.start(queue: .global())
        defer { client.cancel() }

        // The full G3 identity: the subject, a non-empty DER chain (the leaf is a real certificate),
        // and the leaf's SANs (DevTLSIdentity mints DNS:localhost + IP:127.0.0.1 — RFC 5280 §4.2.1.6).
        let identity = await accepted.value
        #expect(identity?.subject == clientCN)
        let leafBytes = identity?.leafDER ?? []
        #expect(!leafBytes.isEmpty)
        let names = identity?.subjectAlternativeNames ?? []
        #expect(names.contains(.dns("localhost")))
        #expect(names.contains(.ip("127.0.0.1")))
        await transport.shutdown()
    }

    @Test(
        "required client-auth rejects a client that presents no certificate",
        .timeLimit(.minutes(1)))
    func requiredClientAuthRejectsNoCertificate() async throws {
        // `.required` demands an explicit verify hook (audit F4); the rejection here is by the missing
        // client cert, not the hook, so accept-any is fine.
        let transport = try Self.mutualTLSTransport { _ in true }
        // No local identity on the client: the required client-auth handshake must fail, so the
        // listener never surfaces a connection (the probe stays empty until it times out).
        try await Self.expectNoConnection(from: transport, clientIdentity: nil)
    }

    @Test("required client-auth without a verifyPeer hook is rejected at setup (audit F4)")
    func requiredClientAuthWithoutHookIsRejected() async throws {
        // Fail closed: a `.required` listener with no verify hook would otherwise accept ANY presented
        // client certificate, so the configuration must be rejected up front rather than silently trust
        // every client.
        let transport = try Self.mutualTLSTransport()  // nil verifyPeer
        await #expect(throws: TransportError.self) {
            _ = try await transport.start()
        }
    }

    @Test(
        "a verifyPeer pin rejects a client whose certificate is not allowed",
        .timeLimit(.minutes(1)))
    func verifyPeerPinRejectsDisallowedCertificate() async throws {
        let clientIdentity = try Self.clientIdentity(commonName: "unpinned-client")
        // A pin that refuses every presented chain — no chain can satisfy an empty allowlist.
        let transport = try Self.mutualTLSTransport { _ in false }
        try await Self.expectNoConnection(from: transport, clientIdentity: clientIdentity)
    }

    @Test(
        "a verifyPeer pin receives the DER chain leaf-first and admits a match",
        .timeLimit(.minutes(1)))
    func verifyPeerPinAdmitsMatchingChain() async throws {
        let clientIdentity = try Self.clientIdentity(commonName: "pinned-client")
        let sawNonEmptyLeaf = Mutex(false)
        // Accept only a present chain whose leaf (first element) carries real DER bytes — proving the
        // `sec_protocol_metadata_access_peer_certificate_chain` → `SecCertificateCopyData` path works.
        let transport = try Self.mutualTLSTransport { chain in
            let admit = chain.first.map { !$0.isEmpty } ?? false
            if admit { sawNonEmptyLeaf.withLock { $0 = true } }
            return admit
        }
        let connections = try await transport.start()
        let port = try #require(NWEndpoint.Port(rawValue: transport.boundPort))

        let accepted = Task { () -> String? in
            var iterator = connections.makeAsyncIterator()
            guard let connection = await iterator.next() else {
                return nil
            }
            defer { Task { await connection.close() } }
            return connection.tlsPeerSubject
        }

        let client = NWConnection(
            host: "127.0.0.1", port: port, using: Self.clientParameters(identity: clientIdentity)
        )
        client.start(queue: .global())
        defer { client.cancel() }

        #expect(await accepted.value == "pinned-client")
        let admittedNonEmptyLeaf: Bool = sawNonEmptyLeaf.withLock(\.self)
        #expect(admittedNonEmptyLeaf)
        await transport.shutdown()
    }

    // MARK: - Helpers

    /// A `.required` client-auth Network.framework transport on an ephemeral port, optionally pinning.
    private static func mutualTLSTransport(
        verifyPeer: (@Sendable ([[UInt8]]) -> Bool)? = nil
    ) throws -> NetworkFrameworkTransport {
        var tls = try SharedDevTLSIdentity.value()
        tls.clientAuth = .required
        tls.verifyPeer = verifyPeer
        return NetworkFrameworkTransport(
            configuration: TransportConfiguration(port: 0, backbone: .networkFramework, tls: tls)
        )
    }

    /// Imports a freshly minted self-signed client identity for `commonName`.
    private static func clientIdentity(commonName: String) throws -> sec_identity_t {
        let tls = try DevTLSIdentity.selfSigned(commonName: commonName)
        return try NetworkFrameworkTLS.identity(pkcs12: tls.pkcs12, passphrase: tls.passphrase)
    }

    /// Asserts the listener surfaces **no** connection for a client presenting `clientIdentity` (or
    /// none): the handshake fails before `.ready`, so the accept boundary is never reached.
    private static func expectNoConnection(
        from transport: NetworkFrameworkTransport,
        clientIdentity: sec_identity_t?
    ) async throws {
        let connections = try await transport.start()
        let port = try #require(NWEndpoint.Port(rawValue: transport.boundPort))

        let yielded = AsyncEventProbe<Void>()
        let accepting = Task {
            var iterator = connections.makeAsyncIterator()
            if await iterator.next() != nil { yielded.record(()) }
        }
        defer { accepting.cancel() }

        let client = NWConnection(
            host: "127.0.0.1", port: port, using: clientParameters(identity: clientIdentity)
        )
        client.start(queue: .global())
        defer { client.cancel() }

        // A surfaced connection would record into the probe; its absence is proven by the timeout.
        await #expect(throws: AsyncEventProbeTimeoutError.self) {
            _ = try await yielded.wait(forAtLeast: 1, timeout: .seconds(2))
        }
        await transport.shutdown()
    }

    /// TLS client parameters trusting the self-signed dev server certificate (test only) and, when
    /// given, presenting `identity` as the client certificate via `set_local_identity`.
    private static func clientParameters(identity: sec_identity_t?) -> NWParameters {
        let options = NWProtocolTLS.Options()
        let security = options.securityProtocolOptions
        if let identity {
            sec_protocol_options_set_local_identity(security, identity)
        }
        sec_protocol_options_set_verify_block(
            security,
            { _, _, complete in complete(true) },
            DispatchQueue.global()
        )
        return NWParameters(tls: options)
    }
}
