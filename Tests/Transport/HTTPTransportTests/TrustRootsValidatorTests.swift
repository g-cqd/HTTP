//
//  TrustRootsValidatorTests.swift
//  HTTPTransportTests
//
//  The G3 trust-roots seam: `TransportTLS.chainValidator(roots:)` performs real X.509 path
//  validation (RFC 5280 §6) with the anchor set pinned to the given roots — a CA-issued leaf
//  validates, a stranger (self-signed) leaf does not, and the degenerate inputs fail closed. Driven
//  by openssl-minted fixtures (a dev CA and a leaf it issued), so the signatures are genuine.
//

import Testing

@testable import HTTPTransport

@Suite("G3 — trust-roots verifyPeer seam (RFC 5280 §6 path validation)")
struct TrustRootsValidatorTests {
    @Test(
        "a CA-issued leaf validates to that CA; a stranger leaf does not",
        .timeLimit(.minutes(1)))
    func issuedLeafValidatesAndStrangerFails() throws {
        let issued = try DevTLSIdentity.issuedChainDER()
        let validator = TransportTLS.chainValidator(roots: [issued.authority])
        #expect(validator([issued.leaf]))

        // A self-signed certificate from a different key is NOT admitted by these roots.
        let strangerPEM = try DevTLSIdentity.selfSignedPEM(commonName: "stranger")
        let stranger = try #require(
            PEMDocument.parse(strangerPEM.certificatePEM)
                .first { $0.label == "CERTIFICATE" }
        )
        #expect(!validator([stranger.der]))
    }

    @Test("the validator fails closed on degenerate inputs")
    func failsClosedOnDegenerateInputs() throws {
        let issued = try DevTLSIdentity.issuedChainDER()
        let validator = TransportTLS.chainValidator(roots: [issued.authority])
        #expect(!validator([]))  // no chain
        #expect(!validator([[0x30, 0x03, 0x01, 0x01, 0x00]]))  // undecodable "certificate"
        let empty = TransportTLS.chainValidator(roots: [])
        #expect(!empty([issued.leaf]))  // no roots — nothing can validate
    }

    @Test("the roots are the ONLY anchors — a root does not admit an unrelated CA's leaf")
    func anchorsArePinned() throws {
        let authorityA = try DevTLSIdentity.issuedChainDER(leafCommonName: "client-a")
        let authorityB = try DevTLSIdentity.issuedChainDER(leafCommonName: "client-b")
        let validator = TransportTLS.chainValidator(roots: [authorityA.authority])
        #expect(validator([authorityA.leaf]))
        #expect(!validator([authorityB.leaf]))
    }
}
