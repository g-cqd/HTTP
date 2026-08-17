//
//  RSAIdentityParityTests.swift
//  HTTPTLSTests
//
//  The identity-loading PARITY gate (3c): the RSA-2048 dev identities the PortableTLS
//  suites mint (`DevTLSIdentity`, openssl-shelled — deliberately, because loading exactly
//  those PEMs is the point) must load into the engine through `HTTPTLSRSA` and serve a
//  full 1-RTT whose RSA-PSS CertificateVerify the client VERIFIES (§4.4.3; §4.2.3's PSS
//  profile: MGF1 with the digest's hash, salt length = digest length). Also pins the typed
//  refusal in `HTTPTLS` proper: an RSA key without the RSA module is
//  `rsaKeyRequiresRSASigner`, not a decode mystery. One dev identity is minted per suite
//  run (the `SharedDevTLSIdentity` lesson: openssl spawns are the slow, flaky part).
//

import Crypto
import HTTPTLSRSA
import HTTPTransport
import Testing

@testable internal import HTTPTLS

@Suite("RSA identity parity — the dev identities load and serve via HTTPTLSRSA")
struct RSAIdentityParityTests {
    /// The one openssl-minted RSA dev identity for this suite (PEM chain + key).
    private static let devIdentity: (certificatePEM: String, privateKeyPEM: String)? =
        try? DevTLSIdentity.selfSignedPEM()

    @Test("the RSA-2048 dev PEM identity loads with the RSA signer")
    func devIdentityLoads() throws {
        let dev = try #require(Self.devIdentity)
        let identity = try TLSCertificateIdentity(
            certificateChainPEM: dev.certificatePEM,
            signer: TLSRSAIdentitySigner(privateKeyPEM: dev.privateKeyPEM)
        )
        #expect(identity.certificateChainDER.count == 1)
    }

    @Test("without HTTPTLSRSA the same key is a TYPED refusal, not a decode error")
    func rsaKeyWithoutSignerIsTyped() throws {
        let dev = try #require(Self.devIdentity)
        #expect(throws: TLSIdentityError.rsaKeyRequiresRSASigner) {
            _ = try TLSPrivateKey(pemRepresentation: dev.privateKeyPEM)
        }
    }

    @Test("a full 1-RTT under the dev identity: rsa_pss_rsae_sha256, client-verified")
    func rsaHandshakeVerifies() async throws {
        let dev = try #require(Self.devIdentity)
        var server = TLSServerConnection(
            configuration: TLSServerConfiguration(),
            identity: try TLSCertificateIdentity(
                certificateChainPEM: dev.certificatePEM,
                signer: TLSRSAIdentitySigner(privateKeyPEM: dev.privateKeyPEM)
            )
        )
        let client = try await CertificateIdentityHandshakeTests.completeHandshake(
            server: &server
        ) {
            $0.signatureAlgorithms = [0x0804]  // rsa_pss_rsae_sha256 only
        }
        let verify = try #require(
            client.serverMessages.first { $0.type == .certificateVerify }
        )
        #expect(try TLSCertificateVerify.parse(verify).scheme == .rsaPssRsaeSha256)
        #expect(
            try CertificateIdentityHandshakeTests.verifyServerCertificateVerify(
                client, verifier: TLSRSACertificateVerifier()
            )
        )
    }

    @Test("an RSA CLIENT certificate verifies through TLSRSACertificateVerifier")
    func rsaClientCertificateVerifies() async throws {
        let dev = try #require(Self.devIdentity)
        let clientSigner = try TLSRSAIdentitySigner(privateKeyPEM: dev.privateKeyPEM)
        let clientLeaf = TestCertificates.certificate(
            aroundSubjectPublicKeyInfo: clientSigner.subjectPublicKeyInfoDER
        )
        let serverCA = try TestPKI.certificateAuthority()
        let serverLeaf = try TestPKI.issued(commonName: "server.test", by: serverCA)
        var configuration = TLSServerConfiguration()
        configuration.clientAuthentication = .required
        configuration.certificateVerifier = TLSRSACertificateVerifier()
        var server = TLSServerConnection(
            configuration: configuration,
            identity: try TLSCertificateIdentity(
                certificateChainDER: [serverLeaf.der],
                signer: TLSPrivateKey.p256(serverLeaf.key)
            )
        )
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        // The client's §4.4.3 RSA-PSS CertificateVerify over CH..client Certificate.
        var wire = try client.sendFlight(
            [client.certificateMessage(chain: [clientLeaf])], promote: false
        )
        let signature = try clientSigner.signature(
            over: TLSCertificateVerify.signedContent(
                context: TLSCertificateVerify.clientContext,
                transcriptHash: client.transcript.currentHash
            ),
            candidates: [.rsaPssRsaeSha256]
        )
        let verifyMessage = TLSCertificateVerify(
            scheme: signature.scheme, signature: signature.bytes
        )
        .encoded()
        wire += try client.sendFlight([verifyMessage], promote: false)
        wire += try client.sendFlight([try client.finishedMessage()])
        _ = try await server.receive(wire)
        #expect(server.state == .connected)
        #expect(server.negotiated?.clientCertificateChainDER == [clientLeaf])
    }
}
