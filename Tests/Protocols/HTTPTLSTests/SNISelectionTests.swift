//
//  SNISelectionTests.swift
//  HTTPTLSTests
//
//  SNI multi-cert selection (RFC 6066 §3) — the engine-side mirror of
//  `PortableTLSSNITests`, same semantics as the portable backbone's `strcmp` callback: the
//  handshake's `server_name` picks the matching identity's chain; an unmatched name, or a
//  client that sends no SNI, is served the default. The served LEAF is the oracle, exactly
//  as the libssl client reads back which certificate it was handed.
//

import Testing

@testable internal import HTTPTLS

@Suite("SNI multi-cert — server_name selects the identity, else the default")
struct SNISelectionTests {
    /// A catalog of three identities whose leaf CNs equal their selection role.
    private static func makeCatalog() throws -> (
        catalog: TLSIdentityCatalog, defaultDER: [UInt8], alphaDER: [UInt8], betaDER: [UInt8]
    ) {
        let authority = try TestPKI.certificateAuthority()
        let fallback = try TestPKI.issued(commonName: "localhost", by: authority)
        let alpha = try TestPKI.issued(commonName: "alpha.test", by: authority)
        let beta = try TestPKI.issued(commonName: "beta.test", by: authority)
        let catalog = TLSIdentityCatalog(
            defaultIdentity: try TLSCertificateIdentity(
                certificateChainDER: [fallback.der], signer: TLSPrivateKey.p256(fallback.key)
            ),
            sniIdentities: [
                "alpha.test": try TLSCertificateIdentity(
                    certificateChainDER: [alpha.der], signer: TLSPrivateKey.p256(alpha.key)
                ),
                "beta.test": try TLSCertificateIdentity(
                    certificateChainDER: [beta.der], signer: TLSPrivateKey.p256(beta.key)
                )
            ]
        )
        return (catalog, fallback.der, alpha.der, beta.der)
    }

    /// The leaf a full handshake against `selector` serves for `serverName`.
    private static func servedLeaf(
        selector: any TLSIdentitySelector, serverName: String?
    ) async throws -> [UInt8] {
        var server = TLSServerConnection(
            configuration: TLSServerConfiguration(), identitySelector: selector
        )
        let client = try await CertificateIdentityHandshakeTests.completeHandshake(
            server: &server
        ) { $0.serverName = serverName }
        return try CertificateIdentityHandshakeTests.servedChain(client)[0]
    }

    @Test("exact host match wins; unmatched and absent SNI fall back to the default")
    func selectionMatchesPortableSemantics() async throws {
        let fixtures = try Self.makeCatalog()
        #expect(
            try await Self.servedLeaf(selector: fixtures.catalog, serverName: "alpha.test")
                == fixtures.alphaDER
        )
        #expect(
            try await Self.servedLeaf(selector: fixtures.catalog, serverName: "beta.test")
                == fixtures.betaDER
        )
        #expect(
            try await Self.servedLeaf(selector: fixtures.catalog, serverName: "unmatched.test")
                == fixtures.defaultDER
        )
        #expect(
            try await Self.servedLeaf(selector: fixtures.catalog, serverName: nil)
                == fixtures.defaultDER
        )
    }

    @Test("the negotiated parameters carry the client's server_name")
    func negotiatedServerNameSurfaces() async throws {
        let fixtures = try Self.makeCatalog()
        var server = TLSServerConnection(
            configuration: TLSServerConfiguration(), identitySelector: fixtures.catalog
        )
        _ = try await CertificateIdentityHandshakeTests.completeHandshake(
            server: &server
        ) { $0.serverName = "alpha.test" }
        #expect(server.negotiated?.serverName == "alpha.test")
    }
}
