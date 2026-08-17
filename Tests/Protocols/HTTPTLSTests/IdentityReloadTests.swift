//
//  IdentityReloadTests.swift
//  HTTPTLSTests
//
//  Hot identity reload via ``TLSIdentityStore`` — the engine-side mirror of
//  `PortableTLSReloadTests` (G4b): after `replace(with:)`, handshakes that resolve serve
//  the NEW identity (no listener restart — identities resolve per handshake at
//  ClientHello); connections established under the old identity keep serving. The store is
//  the object Phase 3d hands to every connection: reload is one call on the store.
//

import Testing

@testable internal import HTTPTLS

@Suite("Hot identity reload — new handshakes swap, established connections keep serving")
struct IdentityReloadTests {
    @Test("replace(with:) swaps the served certificate for later handshakes only")
    func reloadSwapsForNewHandshakes() async throws {
        let authority = try TestPKI.certificateAuthority()
        let first = try TestPKI.issued(commonName: "reload-cert-a", by: authority)
        let second = try TestPKI.issued(commonName: "reload-cert-b", by: authority)
        let store = TLSIdentityStore(
            identity: try TLSCertificateIdentity(
                certificateChainDER: [first.der], signer: TLSPrivateKey.p256(first.key)
            )
        )

        // Connection 1 handshakes under identity A and stays connected.
        var establishedServer = TLSServerConnection(
            configuration: TLSServerConfiguration(), identitySelector: store
        )
        var establishedClient = try await CertificateIdentityHandshakeTests.completeHandshake(
            server: &establishedServer
        )
        #expect(
            try CertificateIdentityHandshakeTests.servedChain(establishedClient)[0]
                == first.der
        )

        // Connection 2 is CONSTRUCTED before the reload — identities resolve at
        // ClientHello, so it must still pick up the swap (the 3d construction order).
        var laterServer = TLSServerConnection(
            configuration: TLSServerConfiguration(), identitySelector: store
        )
        store.replace(
            with: TLSIdentityCatalog(
                defaultIdentity: try TLSCertificateIdentity(
                    certificateChainDER: [second.der], signer: TLSPrivateKey.p256(second.key)
                )
            )
        )
        let laterClient = try await CertificateIdentityHandshakeTests.completeHandshake(
            server: &laterServer
        )
        #expect(
            try CertificateIdentityHandshakeTests.servedChain(laterClient)[0] == second.der
        )

        // The established connection is unaffected: it still serves application data.
        try establishedServer.send(applicationData: [0x0A])
        try establishedClient.absorb(establishedServer.outboundBytes())
        #expect(establishedClient.applicationData == [[0x0A]])
    }
}
