//
//  CertificateReloadTests.swift
//  HTTPTransportTests
//
//  G4b — hot TLS certificate reload. The Network.framework backbone rebinds its listener with a new
//  identity on the same port (`allowLocalEndpointReuse` overlap) while already-accepted connections
//  keep serving on the identity they handshook with. The real-loopback gate: start on cert A, hold a
//  connection open, reload to cert B, and prove a *new* connection's client verify-block sees cert B's
//  subject while the *old* connection still round-trips (zero existing-connection drops). The other
//  backbones throw `TransportError.unsupported` via the `ServerTransport` protocol default.
//

internal import Dispatch
import HTTPTestSupport
internal import Network
internal import Security
import Testing

@testable import HTTPTransport

@Suite("Transport — hot TLS certificate reload (G4b)")
struct CertificateReloadTests {
    @Test(
        "a reload swaps the served identity for new connections while existing ones keep serving",
        .timeLimit(.minutes(1)))
    func reloadSwapsIdentityAndPreservesConnections() async throws {
        let certA = try DevTLSIdentity.selfSigned(commonName: "reload-cert-A")
        let certB = try DevTLSIdentity.selfSigned(commonName: "reload-cert-B")
        let transport = NetworkFrameworkTransport(
            configuration: TransportConfiguration(port: 0, backbone: .networkFramework, tls: certA)
        )
        let accepted = try await transport.start()
        let port = try #require(NWEndpoint.Port(rawValue: transport.boundPort))

        // Server: echo each accepted connection's bytes for its lifetime, so a client round-trip
        // proves the connection is alive. A reloaded listener feeds this same stream.
        let server = Task {
            await withDiscardingTaskGroup { group in
                for await connection in accepted {
                    group.addTask {
                        while let chunk = try? await connection.receive(maxLength: 256),
                            !chunk.isEmpty
                        {
                            try? await connection.send(chunk)
                        }
                        await connection.close()
                    }
                }
            }
        }
        defer { server.cancel() }

        // Client 1 on cert A: its verify-block records the server's leaf subject; keep it open.
        let subjectA = AsyncEventProbe<String>()
        let client1 = NWConnection(
            host: "127.0.0.1", port: port, using: Self.observingClient(subjectA)
        )
        let wrapped1 = NetworkFrameworkConnection(
            id: TransportConnectionID(1_001),
            connection: client1,
            negotiatedApplicationProtocol: nil,
            isSecure: true
        )
        client1.start(queue: .global())
        defer { client1.cancel() }
        let observedA = try await subjectA.wait(forAtLeast: 1)
        #expect(observedA.first == "reload-cert-A")

        // Hot-reload to cert B (rebinds the listener on the same port).
        try await transport.reload(tls: certB)

        // Client 2 connects after the reload → its verify-block must see the NEW identity (cert B).
        let subjectB = AsyncEventProbe<String>()
        let client2 = NWConnection(
            host: "127.0.0.1", port: port, using: Self.observingClient(subjectB)
        )
        client2.start(queue: .global())
        defer { client2.cancel() }
        let observedB = try await subjectB.wait(forAtLeast: 1)
        #expect(observedB.first == "reload-cert-B")

        // The existing connection (client 1, cert A) must still round-trip — zero existing drops.
        let payload = Array("still-alive".utf8)
        try await wrapped1.send(payload)
        let echo = try await wrapped1.receive(maxLength: 256)
        #expect(echo == payload)

        await wrapped1.close()
        await transport.shutdown()
    }

    @Test("reload is unsupported on a non-Network.framework backbone (the protocol default)")
    func reloadUnsupportedOnNonNetworkBackbone() async throws {
        let tls = try SharedDevTLSIdentity.value()
        let unsupported = TransportError.unsupported(
            "TLS reload is unsupported by the fake backbone"
        )
        await #expect(throws: unsupported) {
            try await FakeTransport().reload(tls: tls)
        }
    }

    // MARK: - Helpers

    /// TLS client parameters whose verify-block records the *server's* leaf certificate subject into
    /// `subject` (then accepts the dev certificate — test only).
    private static func observingClient(_ subject: AsyncEventProbe<String>) -> NWParameters {
        let options = NWProtocolTLS.Options()
        let security = options.securityProtocolOptions
        sec_protocol_options_set_verify_block(
            security,
            { metadata, _, complete in
                if let leaf = leafSubject(of: metadata) {
                    subject.record(leaf)
                }
                complete(true)
            },
            DispatchQueue.global()
        )
        return NWParameters(tls: options)
    }

    /// The subject summary of the peer's leaf certificate (the server, from the client's view).
    private static func leafSubject(of metadata: sec_protocol_metadata_t) -> String? {
        var subject: String?
        var captured = false
        _ = sec_protocol_metadata_access_peer_certificate_chain(metadata) { secCertificate in
            guard !captured else {
                return
            }
            captured = true
            let certificate = sec_certificate_copy_ref(secCertificate).takeRetainedValue()
            if let summary = SecCertificateCopySubjectSummary(certificate) {
                subject = summary as String
            }
        }
        return subject
    }
}
