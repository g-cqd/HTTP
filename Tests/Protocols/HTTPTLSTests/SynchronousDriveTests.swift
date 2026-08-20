//
//  SynchronousDriveTests.swift
//  HTTPTLSTests
//
//  Phase 3d — the full synchronous drive (`receiveSynchronously`): the same 1-RTT handshake,
//  client-auth trust seam, and steady state as the async drive, without a suspension point —
//  what the portable TLS backbone's engine adapter runs under its `Mutex`. The fail-closed
//  arms matter as much as the happy path: an identity or validator that only offers the
//  async surface must abort (`internal_error`), never silently degrade or hidden-wait.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("Synchronous drive — the no-suspension twin of receive")
struct SynchronousDriveTests {
    /// A server over a real, synchronously-signing certificate identity.
    private static func makeConnection(
        clientAuthentication: TLSClientAuthenticationMode = .none,
        validator: (any TLSClientChainValidator)? = nil
    ) throws -> TLSServerConnection {
        let authority = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(commonName: "sync.test", by: authority)
        var configuration = TLSServerConfiguration()
        configuration.clientAuthentication = clientAuthentication
        configuration.clientChainValidator = validator
        return TLSServerConnection(
            configuration: configuration,
            identity: try TLSCertificateIdentity(
                certificateChainPEM: leaf.pem + "\n" + authority.pem,
                privateKeyPEM: leaf.keyPEM
            )
        )
    }

    @Test("a full 1-RTT handshake, echo, and KeyUpdate complete without suspension")
    func fullHandshakeSynchronously() throws {
        var server = try Self.makeConnection()
        var client = HandshakeTestClient()
        _ = try server.receiveSynchronously(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        let events = try server.receiveSynchronously(try client.finishHandshake())
        #expect(server.state == .connected)
        guard case .handshakeCompleted = events.first else {
            Issue.record("expected completion, got \(events)")
            return
        }
        // Steady state rides the same drive: data in, KeyUpdate honored, data out.
        let echoed = try server.receiveSynchronously(
            try client.applicationDataRecord([0x70, 0x69, 0x6E, 0x67])
        )
        #expect(echoed == [.applicationData([0x70, 0x69, 0x6E, 0x67])])
        _ = try server.receiveSynchronously(try client.keyUpdateRecord(requesting: true))
        try server.send(applicationData: [0x70, 0x6F, 0x6E, 0x67])
        try client.absorb(server.outboundBytes())
        #expect(client.applicationData.last == [0x70, 0x6F, 0x6E, 0x67])
    }

    @Test("an async-only identity provider fails closed on the synchronous drive")
    func asyncOnlyIdentityFailsClosed() throws {
        var server = TLSServerConnection(
            configuration: TLSServerConfiguration(), identity: P256TestIdentity()
        )
        var client = HandshakeTestClient()
        #expect(
            throws: TLSHandshakeError.internalError(
                "the identity provider cannot sign on the synchronous drive"
            )
        ) {
            _ = try server.receiveSynchronously(try client.helloRecord())
        }
        guard case .failed = server.state else {
            Issue.record("expected a terminal failure, got \(server.state)")
            return
        }
        // The funnel owes the §6.2 internal_error alert (ServerHello may precede it — the
        // failure lands mid-flight, after the hello already entered the outbound queue).
        #expect(!server.outboundBytes().isEmpty)
    }

    @Test(
        "a synchronous verifyPeer hook judges a presented chain",
        arguments: [true, false]
    )
    func hookJudgesPresentedChain(accepts: Bool) throws {
        var server = try Self.makeConnection(
            clientAuthentication: .optional,
            validator: TLSVerifyPeerHookValidator { _ in accepts }
        )
        var client = HandshakeTestClient()
        _ = try server.receiveSynchronously(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        let signingKey = P256.Signing.PrivateKey()
        let leaf = TestCertificates.certificate(
            aroundSubjectPublicKeyInfo: [UInt8](signingKey.publicKey.derRepresentation)
        )
        var wire = try client.sendFlight(
            [client.certificateMessage(chain: [leaf])], promote: false
        )
        wire += try client.sendFlight(
            [try client.certificateVerifyMessage(signingKey: signingKey)], promote: false
        )
        wire += try client.sendFlight([try client.finishedMessage()])
        if accepts {
            let events = try server.receiveSynchronously(wire)
            guard case .handshakeCompleted(let negotiated) = events.first else {
                Issue.record("expected completion, got \(events)")
                return
            }
            #expect(negotiated.clientCertificateChainDER == [leaf])
        }
        else {
            #expect(
                throws: TLSHandshakeError.clientChainRejected(
                    .badCertificate("verifyPeer hook rejected")
                )
            ) {
                _ = try server.receiveSynchronously(wire)
            }
        }
    }

    @Test("an async-only chain validator fails closed on the synchronous drive")
    func asyncOnlyValidatorFailsClosed() throws {
        // A validator that offers only the async surface.
        struct AsyncOnlyValidator: TLSClientChainValidator {
            func validate(chainDER _: [[UInt8]]) async -> TLSChainVerdict { .accepted }
        }
        var server = try Self.makeConnection(
            clientAuthentication: .optional, validator: AsyncOnlyValidator()
        )
        var client = HandshakeTestClient()
        _ = try server.receiveSynchronously(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        let signingKey = P256.Signing.PrivateKey()
        let leaf = TestCertificates.certificate(
            aroundSubjectPublicKeyInfo: [UInt8](signingKey.publicKey.derRepresentation)
        )
        let wire = try client.sendFlight(
            [client.certificateMessage(chain: [leaf])], promote: false
        )
        #expect(
            throws: TLSHandshakeError.internalError(
                "the client-chain validator cannot judge on the synchronous drive"
            )
        ) {
            _ = try server.receiveSynchronously(wire)
        }
    }
}
