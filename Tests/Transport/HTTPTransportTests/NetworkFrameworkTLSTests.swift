//
//  NetworkFrameworkTLSTests.swift
//  HTTPTransportTests
//
//  TLS + ALPN coverage for the Network.framework backbone: a dev PKCS#12 identity round-trips through
//  SecPKCS12Import, and a real loopback handshake negotiates ALPN "h2" (RFC 7301) — the value the
//  server uses to commit a connection to HTTP/2 (RFC 9113 §3.3).
//

internal import Dispatch
import HTTPTestSupport
internal import Network
internal import Security
import Testing

@testable import HTTPTransport

@Suite("Network.framework backbone — TLS + ALPN")
struct NetworkFrameworkTLSTests {
    @Test("a dev self-signed identity imports through SecPKCS12Import (PKCS#12 round-trip)")
    func devIdentityImports() throws {
        let tls = try SharedDevTLSIdentity.value()
        #expect(!tls.pkcs12.isEmpty)
        #expect(tls.applicationProtocols.contains("h2"))
        // The blob must import into a sec_identity — the exact path the server takes on bind.
        _ = try NetworkFrameworkTLS.identity(pkcs12: tls.pkcs12, passphrase: tls.passphrase)
    }

    @Test("a PEM identity is rejected at start() with the documented Security limitation (G3)")
    func pemIdentityIsRejectedWithGuidance() async throws {
        // Security offers no public in-memory certificate + key → SecIdentity constructor, so the
        // Network backbone must fail closed at start() — with guidance — rather than mis-load an
        // empty PKCS#12 (the portable backbone consumes PEM natively).
        let pem = try DevTLSIdentity.selfSignedPEM()
        let tls = TransportTLS(
            pem: TransportTLS.PEMIdentity(
                certificateChainPEM: pem.certificatePEM, privateKeyPEM: pem.privateKeyPEM
            )
        )
        let transport = NetworkFrameworkTransport(
            configuration: TransportConfiguration(port: 0, backbone: .networkFramework, tls: tls)
        )
        await #expect(throws: TransportError.self) {
            _ = try await transport.start()
        }
    }

    @Test("concurrent PKCS#12 imports all succeed — SecPKCS12Import is serialized, not raced")
    func concurrentImportsAreSerialized() async throws {
        let tls = try SharedDevTLSIdentity.value()
        // SecPKCS12Import is not thread-safe; the backbone serializes it. Fan many imports out at
        // once: every one must succeed. Without the lock this races intermittently with an
        // internal/MAC error (the flake this guards against) — here it is deterministic.
        let count = 32
        let succeeded = await withTaskGroup(of: Bool.self) { group in
            for _ in 0 ..< count {
                group.addTask {
                    let identity = try? NetworkFrameworkTLS.identity(
                        pkcs12: tls.pkcs12,
                        passphrase: tls.passphrase
                    )
                    return identity != nil
                }
            }
            return await group.reduce(into: 0) { $0 += $1 ? 1 : 0 }
        }
        #expect(succeeded == count)
    }

    @Test(
        "negotiates ALPN h2 over TLS and reports it on the accepted connection",
        .timeLimit(.minutes(1)))
    func negotiatesHTTP2OverTLS() async throws {
        let tls = try SharedDevTLSIdentity.value()
        let transport = NetworkFrameworkTransport(
            configuration: TransportConfiguration(port: 0, backbone: .networkFramework, tls: tls)
        )
        let connections = try await transport.start()
        let port = try #require(NWEndpoint.Port(rawValue: transport.boundPort))

        // Server: the accepted connection is surfaced only after `.ready`, so its ALPN is settled.
        let accepted = Task { () -> String? in
            var iterator = connections.makeAsyncIterator()
            guard let connection = await iterator.next() else {
                return nil
            }
            defer { Task { await connection.close() } }
            return connection.negotiatedApplicationProtocol
        }

        // Client: offer ALPN "h2" and accept the self-signed dev certificate (test only).
        let client = NWConnection(host: "127.0.0.1", port: port, using: Self.clientParameters())
        client.start(queue: .global())
        defer { client.cancel() }

        #expect(await accepted.value == "h2")
        await transport.shutdown()
    }

    /// TLS client parameters advertising ALPN `h2` and trusting any certificate (dev/test only).
    private static func clientParameters() -> NWParameters {
        let options = NWProtocolTLS.Options()
        let security = options.securityProtocolOptions
        "h2".withCString { sec_protocol_options_add_tls_application_protocol(security, $0) }
        sec_protocol_options_set_verify_block(
            security,
            { _, _, complete in complete(true) },
            DispatchQueue.global()
        )
        return NWParameters(tls: options)
    }
}
