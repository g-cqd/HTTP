//
//  CertificateIdentityHandshakeTests.swift
//  HTTPTLSTests
//
//  Full 1-RTT handshakes served by the REAL identity (RFC 8446 §4.4.2/§4.4.3): the in-test
//  client (the engine's own primitives, driven from the client side — the RFC 8448
//  technique) completes the handshake, asserts the served chain byte-for-byte, and
//  VERIFIES the server's CertificateVerify like a real peer would — recomputing
//  Transcript-Hash(CH..Certificate), rebuilding the §4.4.3 content, and checking the
//  signature against the leaf's SubjectPublicKeyInfo with the module's own verifier.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("Certificate identity — real 1-RTT handshakes, client-verified")
struct CertificateIdentityHandshakeTests {
    /// Drives one full handshake + application-data echo; returns the client afterwards.
    static func completeHandshake(
        server: inout TLSServerConnection,
        configure: ((inout TestClientHello) -> Void)? = nil
    ) async throws -> HandshakeTestClient {
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord(configure: configure))
        try client.absorb(server.outboundBytes())
        let events = try await server.receive(try client.finishHandshake())
        #expect(server.state == .connected)
        guard case .handshakeCompleted = events.first else {
            throw TLSHandshakeError.internalError("expected completion, got \(events)")
        }
        return client
    }

    /// The §4.4.2 chain the server sent, parsed from the client's message log.
    static func servedChain(_ client: HandshakeTestClient) throws -> [[UInt8]] {
        guard
            let message = client.serverMessages.first(where: { $0.type == .certificate })
        else {
            throw TLSHandshakeError.internalError("no Certificate message")
        }
        return try TLSCertificateCodec.parseClientCertificate(message)
    }

    /// Recomputes the transcript hash through the server Certificate and verifies the
    /// CertificateVerify against the leaf SPKI — §4.4.3, exactly as a client must.
    static func verifyServerCertificateVerify(
        _ client: HandshakeTestClient,
        verifier: any TLSCertificateSignatureVerifier = TLSECDSACertificateVerifier()
    ) throws -> Bool {
        var transcript = TLSTranscriptHash(.sha256)
        transcript.append(client.helloMessageRaw)
        for message in client.serverMessages {
            if message.type == .certificateVerify {
                let verify = try TLSCertificateVerify.parse(message)
                let leaf = try servedChain(client)[0]
                return verifier.verify(
                    scheme: verify.scheme,
                    signature: verify.signature,
                    content: TLSCertificateVerify.signedContent(
                        context: TLSCertificateVerify.serverContext,
                        transcriptHash: transcript.currentHash
                    ),
                    subjectPublicKeyInfoDER: try DERPublicKeyLocator.subjectPublicKeyInfo(
                        inCertificateDER: leaf
                    )
                )
            }
            transcript.append(message.raw)
        }
        throw TLSHandshakeError.internalError("no CertificateVerify message")
    }

    @Test("a P-256 identity serves its chain and a signature the client validates")
    func p256IdentityHandshake() async throws {
        let authority = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(commonName: "server.test", by: authority)
        let identity = try TLSCertificateIdentity(
            certificateChainPEM: leaf.pem + "\n" + authority.pem,
            privateKeyPEM: leaf.keyPEM
        )
        var server = TLSServerConnection(
            configuration: TLSServerConfiguration(), identity: identity
        )
        var client = try await Self.completeHandshake(server: &server)
        #expect(try Self.servedChain(client) == [leaf.der, authority.der])
        #expect(try Self.verifyServerCertificateVerify(client))

        // The connection serves after the handshake — application data both ways.
        try server.send(applicationData: [0x68, 0x69])
        try client.absorb(server.outboundBytes())
        #expect(client.applicationData == [[0x68, 0x69]])
    }

    @Test("an Ed25519 identity negotiates the ed25519 scheme end to end")
    func ed25519IdentityHandshake() async throws {
        let fixture = try TestPKI.ed25519SelfSigned()
        let identity = try TLSCertificateIdentity(
            certificateChainPEM: fixture.certificatePEM, privateKeyPEM: fixture.keyPEM
        )
        var server = TLSServerConnection(
            configuration: TLSServerConfiguration(), identity: identity
        )
        let client = try await Self.completeHandshake(server: &server) {
            $0.signatureAlgorithms = [0x0807]  // ed25519 only — forces the Ed25519 signer
        }
        let verify = try #require(
            client.serverMessages.first { $0.type == .certificateVerify }
        )
        #expect(try TLSCertificateVerify.parse(verify).scheme == .ed25519)
        #expect(try Self.verifyServerCertificateVerify(client))
    }
}
