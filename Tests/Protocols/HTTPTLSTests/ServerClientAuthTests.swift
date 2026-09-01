//
//  ServerClientAuthTests.swift
//  HTTPTLSTests
//
//  RFC 8446 §4.3.2/§4.4.2.4 client authentication, end to end against a real signing client —
//  the semantics table this suite pins is the portable TLS backbone's (its G3 fail-closed
//  audit): `.none` never asks; `.optional` asks, tolerates absence, but a PRESENTED
//  certificate must verify; `.required` aborts absence with `certificate_required`. A good
//  P-256 CertificateVerify passes real swift-crypto verification; a signature over the wrong
//  transcript, under the wrong context string, or from the wrong key is `decrypt_error`.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("Client authentication — the fail-closed §4.4.2.4 matrix")
struct ServerClientAuthTests {
    /// A server with the given client-auth mode and a real P-256 identity.
    private static func makeConnection(
        _ mode: TLSClientAuthenticationMode
    ) -> TLSServerConnection {
        var configuration = TLSServerConfiguration()
        configuration.clientAuthentication = mode
        return TLSServerConnection(
            configuration: configuration, identity: P256TestIdentity()
        )
    }

    /// Runs the first round trip: client hello in, server flight absorbed by the client.
    private static func openHandshake(
        _ server: inout TLSServerConnection, _ client: inout HandshakeTestClient
    ) async throws {
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
    }

    @Test(".none never sends a CertificateRequest")
    func noneNeverAsks() async throws {
        var server = Self.makeConnection(.none)
        var client = HandshakeTestClient()
        try await Self.openHandshake(&server, &client)
        #expect(!client.serverMessages.contains { $0.type == .certificateRequest })
        let events = try await server.receive(try client.finishHandshake())
        #expect(server.state == .connected)
        guard case .handshakeCompleted(let negotiated) = events.first else {
            Issue.record("expected completion")
            return
        }
        #expect(negotiated.clientCertificateChainDER.isEmpty)
    }

    @Test(".optional accepts an empty client Certificate", arguments: [false, true])
    func optionalAcceptsAbsence(sendEmptyCertificate: Bool) async throws {
        var server = Self.makeConnection(.optional)
        var client = HandshakeTestClient()
        try await Self.openHandshake(&server, &client)
        #expect(client.serverMessages.contains { $0.type == .certificateRequest })
        // §4.4.2: a certificate-less client answers the request with an EMPTY Certificate
        // and omits CertificateVerify. (Sequential sends: Finished is computed over the
        // transcript INCLUDING the empty Certificate.)
        var flight: [UInt8]
        if sendEmptyCertificate {
            flight = try client.sendFlight(
                [client.certificateMessage(chain: [])], promote: false
            )
            flight += try client.sendFlight([try client.finishedMessage()])
        }
        else {
            flight = try client.finishHandshake()
        }
        if sendEmptyCertificate {
            let events = try await server.receive(flight)
            #expect(server.state == .connected)
            guard case .handshakeCompleted(let negotiated) = events.first else {
                Issue.record("expected completion")
                return
            }
            #expect(negotiated.clientCertificateChainDER.isEmpty)
        }
        else {
            // Skipping the Certificate entirely after a CertificateRequest is a §4 order
            // violation — WAIT_CERT expects Certificate, not Finished.
            await #expect(throws: TLSHandshakeError.unexpectedMessage(.finished)) {
                _ = try await server.receive(flight)
            }
        }
    }

    @Test(".optional verifies a presented certificate — and accepts a good one")
    func optionalVerifiesPresence() async throws {
        var server = Self.makeConnection(.optional)
        var client = HandshakeTestClient()
        try await Self.openHandshake(&server, &client)
        let signingKey = P256.Signing.PrivateKey()
        let leaf = TestCertificates.certificate(
            aroundSubjectPublicKeyInfo: [UInt8](signingKey.publicKey.derRepresentation)
        )
        // Each sendFlight appends to the client transcript BEFORE sealing, so the
        // CertificateVerify is computed over CH..Certificate exactly as §4.4.3 requires.
        var wire = try client.sendFlight(
            [client.certificateMessage(chain: [leaf])], promote: false
        )
        wire += try client.sendFlight(
            [try client.certificateVerifyMessage(signingKey: signingKey)], promote: false
        )
        wire += try client.sendFlight([try client.finishedMessage()])
        let events = try await server.receive(wire)
        guard case .handshakeCompleted(let negotiated) = events.first else {
            Issue.record("expected completion, got \(events); state \(server.state)")
            return
        }
        #expect(negotiated.clientCertificateChainDER == [leaf])
    }

    @Test(".required aborts an empty client Certificate with certificate_required")
    func requiredRejectsAbsence() async throws {
        var server = Self.makeConnection(.required)
        var client = HandshakeTestClient()
        try await Self.openHandshake(&server, &client)
        let flight = try client.sendFlight(
            [client.certificateMessage(chain: [])], promote: false
        )
        await #expect(throws: TLSHandshakeError.certificateRequired) {
            _ = try await server.receive(flight)
        }
        #expect(server.state == .failed(.certificateRequired))
    }

    @Test("a presented-but-forged CertificateVerify is fatal in BOTH requesting modes")
    func forgedCertificateVerifyIsFatal() async throws {
        for mode in [TLSClientAuthenticationMode.optional, .required] {
            var server = Self.makeConnection(mode)
            var client = HandshakeTestClient()
            try await Self.openHandshake(&server, &client)
            let signingKey = P256.Signing.PrivateKey()
            let otherKey = P256.Signing.PrivateKey()  // signs; the leaf disagrees
            let leaf = TestCertificates.certificate(
                aroundSubjectPublicKeyInfo: [UInt8](signingKey.publicKey.derRepresentation)
            )
            var wire = try client.sendFlight(
                [client.certificateMessage(chain: [leaf])], promote: false
            )
            wire += try client.sendFlight(
                [try client.certificateVerifyMessage(signingKey: otherKey)], promote: false
            )
            await #expect(throws: TLSHandshakeError.invalidCertificateVerify) {
                _ = try await server.receive(wire)
            }
            #expect(server.state == .failed(.invalidCertificateVerify), "\(mode)")
        }
    }

    @Test("a client CertificateVerify under the SERVER context string is fatal (§4.4.3)")
    func wrongContextStringIsFatal() async throws {
        var server = Self.makeConnection(.optional)
        var client = HandshakeTestClient()
        try await Self.openHandshake(&server, &client)
        let signingKey = P256.Signing.PrivateKey()
        let leaf = TestCertificates.certificate(
            aroundSubjectPublicKeyInfo: [UInt8](signingKey.publicKey.derRepresentation)
        )
        var wire = try client.sendFlight(
            [client.certificateMessage(chain: [leaf])], promote: false
        )
        wire += try client.sendFlight(
            [
                try client.certificateVerifyMessage(
                    signingKey: signingKey, context: TLSCertificateVerify.serverContext
                )
            ],
            promote: false
        )
        await #expect(throws: TLSHandshakeError.invalidCertificateVerify) {
            _ = try await server.receive(wire)
        }
    }
}
