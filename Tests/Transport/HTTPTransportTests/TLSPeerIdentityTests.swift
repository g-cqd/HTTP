//
//  TLSPeerIdentityTests.swift
//  HTTPTransportTests
//
//  The G3 richer mTLS context building blocks, off any socket: the RFC 7468 PEM block parser, the
//  RFC 5280 §4.2.1.6 Subject Alternative Name extractor over real (openssl-minted) certificate DER,
//  and the `TLSPeerIdentity` convenience that ties them together. Hostile-input cases prove the DER
//  walk fails soft (returns what it has) instead of trapping or over-reading.
//

import Testing

@testable import HTTPTransport

@Suite("G3 — TLS peer identity (PEM parsing + X.509 SAN extraction)")
struct TLSPeerIdentityTests {
    @Test("PEMDocument splits a certificate + key file into labeled DER blocks (RFC 7468)")
    func pemParsesLabeledBlocks() throws {
        let pem = try DevTLSIdentity.selfSignedPEM()
        let combined = pem.certificatePEM + "\n" + pem.privateKeyPEM
        let blocks = PEMDocument.parse(combined)
        #expect(blocks.count == 2)
        #expect(blocks.first?.label == "CERTIFICATE")
        let derIsNonEmpty = blocks.allSatisfy { !$0.der.isEmpty }
        #expect(derIsNonEmpty)
        // DER always opens with a SEQUENCE tag (X.690) for these structures.
        #expect(blocks.first?.der.first == 0x30)
    }

    @Test("PEMDocument skips unmatched / malformed blocks instead of mis-pairing them")
    func pemSkipsUnmatchedBlocks() {
        let mismatched = """
            -----BEGIN CERTIFICATE-----
            AAAA
            -----END PRIVATE KEY-----
            """
        #expect(PEMDocument.parse(mismatched).isEmpty)
        #expect(PEMDocument.parse("no blocks here").isEmpty)
        let invalidBase64 = """
            -----BEGIN CERTIFICATE-----
            !!!not-base64!!!
            -----END CERTIFICATE-----
            """
        #expect(PEMDocument.parse(invalidBase64).isEmpty)
    }

    @Test("the SAN extractor reads DNS and IP names out of a real certificate (RFC 5280 §4.2.1.6)")
    func extractsSubjectAlternativeNames() throws {
        let pem = try DevTLSIdentity.selfSignedPEM()
        let certificate = try #require(
            PEMDocument.parse(pem.certificatePEM).first { $0.label == "CERTIFICATE" }
        )
        let names = X509SubjectAlternativeNames.extract(certificate.der)
        #expect(names.contains(.dns("localhost")))
        #expect(names.contains(.ip("127.0.0.1")))
    }

    @Test("the SAN extractor fails soft on truncated/garbage DER (no traps, no over-reads)")
    func extractorFailsSoftOnHostileDER() throws {
        #expect(X509SubjectAlternativeNames.extract([]).isEmpty)
        #expect(X509SubjectAlternativeNames.extract([0x30]).isEmpty)  // tag with no length
        #expect(X509SubjectAlternativeNames.extract([0x30, 0x84]).isEmpty)  // truncated long form
        #expect(X509SubjectAlternativeNames.extract([0x30, 0x83, 0xFF, 0xFF, 0xFF]).isEmpty)
        // Every truncation of a real certificate must also fail soft.
        let pem = try DevTLSIdentity.selfSignedPEM()
        let certificate = try #require(
            PEMDocument.parse(pem.certificatePEM).first { $0.label == "CERTIFICATE" }
        )
        for cut in stride(from: 0, to: certificate.der.count, by: 97) {
            _ = X509SubjectAlternativeNames.extract(Array(certificate.der.prefix(cut)))
        }
    }

    @Test("TLSPeerIdentity(chainDER:subject:) extracts the leaf's SANs and exposes the leaf DER")
    func identityConvenienceExtractsNames() throws {
        let pem = try DevTLSIdentity.selfSignedPEM(commonName: "peer")
        let certificate = try #require(
            PEMDocument.parse(pem.certificatePEM).first { $0.label == "CERTIFICATE" }
        )
        let identity = TLSPeerIdentity(chainDER: [certificate.der], subject: "peer")
        #expect(identity.subject == "peer")
        #expect(identity.leafDER == certificate.der)
        #expect(identity.subjectAlternativeNames.contains(.dns("localhost")))
        let empty = TLSPeerIdentity(chainDER: [], subject: nil)
        #expect(empty.leafDER == nil)
        #expect(empty.subjectAlternativeNames.isEmpty)
    }
}
