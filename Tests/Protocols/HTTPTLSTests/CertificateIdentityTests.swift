//
//  CertificateIdentityTests.swift
//  HTTPTLSTests
//
//  Load-time validation of ``TLSCertificateIdentity`` (RFC 8446 §4.4.2) — the 3c contract
//  that a misconfigured identity dies at STARTUP with a typed ``TLSIdentityError``: empty
//  chains, undecodable certificates, out-of-order chains (issuer names right but the wrong
//  signer, too), leaf/key mismatches, and key algorithms this module cannot sign with.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("Certificate identity — §4.4.2 invariants enforced at load time")
struct CertificateIdentityTests {
    @Test("a PEM chain + PKCS#8 P-256 key loads, leaf first")
    func pemIdentityLoads() throws {
        let authority = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(commonName: "server.test", by: authority)
        let identity = try TLSCertificateIdentity(
            certificateChainPEM: leaf.pem + "\n" + authority.pem,
            privateKeyPEM: leaf.keyPEM
        )
        #expect(identity.certificateChainDER == [leaf.der, authority.der])
    }

    @Test("a DER chain + signer loads, and signs the offered candidate scheme")
    func derIdentitySigns() async throws {
        let authority = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(commonName: "server.test", by: authority)
        let identity = try TLSCertificateIdentity(
            certificateChainDER: [leaf.der, authority.der],
            signer: TLSPrivateKey.p256(leaf.key)
        )
        let signature = try await identity.signature(
            over: [1, 2, 3], algorithms: [.ed25519, .ecdsaSecp256r1Sha256]
        )
        #expect(signature.scheme == .ecdsaSecp256r1Sha256)
        let verified = TLSECDSACertificateVerifier()
            .verify(
                scheme: signature.scheme,
                signature: signature.bytes,
                content: [1, 2, 3],
                subjectPublicKeyInfoDER: [UInt8](leaf.key.publicKey.derRepresentation)
            )
        #expect(verified)
    }

    @Test("an Ed25519 identity loads through the RFC 8410 PKCS#8 path and signs ed25519")
    func ed25519IdentityLoads() async throws {
        let fixture = try TestPKI.ed25519SelfSigned()
        let identity = try TLSCertificateIdentity(
            certificateChainPEM: fixture.certificatePEM, privateKeyPEM: fixture.keyPEM
        )
        let signature = try await identity.signature(
            over: [9, 9, 9], algorithms: [.ecdsaSecp256r1Sha256, .ed25519]
        )
        #expect(signature.scheme == .ed25519)
        #expect(fixture.key.publicKey.isValidSignature(signature.bytes, for: [9, 9, 9]))
    }

    @Test("an empty chain is a typed load error")
    func emptyChainFails() {
        #expect(throws: TLSIdentityError.emptyChain) {
            _ = try TLSCertificateIdentity(
                certificateChainDER: [], signer: TLSPrivateKey.p256(.init())
            )
        }
    }

    @Test("a PEM bundle with no CERTIFICATE block is a typed load error")
    func certificateFreePEMFails() {
        #expect(throws: TLSIdentityError.emptyChain) {
            _ = try TLSCertificateIdentity(
                certificateChainPEM: P256.Signing.PrivateKey().pemRepresentation,
                signer: TLSPrivateKey.p256(.init())
            )
        }
    }

    @Test("an undecodable chain element is a typed load error naming the index")
    func undecodableCertificateFails() throws {
        let authority = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(commonName: "server.test", by: authority)
        do {
            _ = try TLSCertificateIdentity(
                certificateChainDER: [leaf.der, [0xDE, 0xAD]],
                signer: TLSPrivateKey.p256(leaf.key)
            )
            Issue.record("expected a load failure")
        }
        catch {
            guard case .undecodableCertificate(let index, _) = error else {
                Issue.record("expected undecodableCertificate, got \(error)")
                return
            }
            #expect(index == 1)
        }
    }

    @Test("a chain pasted in the wrong order fails at load (§4.4.2 leaf-first)")
    func reversedChainFails() throws {
        let authority = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(commonName: "server.test", by: authority)
        #expect(throws: TLSIdentityError.chainOutOfOrder(index: 1)) {
            _ = try TLSCertificateIdentity(
                certificateChainDER: [authority.der, leaf.der],
                signer: TLSPrivateKey.p256(authority.key)
            )
        }
    }

    @Test("a chain through a FOREIGN intermediate fails: names alone do not certify")
    func foreignIntermediateFails() throws {
        // Same subject/issuer names, but the leaf was signed by `authority`, not `impostor`
        // — the load-time check verifies the certifying SIGNATURE, not just the names.
        let authority = try TestPKI.certificateAuthority(commonName: "Shared CA Name")
        let impostor = try TestPKI.certificateAuthority(commonName: "Shared CA Name")
        let leaf = try TestPKI.issued(commonName: "server.test", by: authority)
        #expect(throws: TLSIdentityError.chainOutOfOrder(index: 1)) {
            _ = try TLSCertificateIdentity(
                certificateChainDER: [leaf.der, impostor.der],
                signer: TLSPrivateKey.p256(leaf.key)
            )
        }
    }

    @Test("a leaf/key mismatch fails at load (§4.4.3 could never verify)")
    func leafKeyMismatchFails() throws {
        let authority = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(commonName: "server.test", by: authority)
        #expect(throws: TLSIdentityError.leafKeyMismatch) {
            _ = try TLSCertificateIdentity(
                certificateChainDER: [leaf.der],
                signer: TLSPrivateKey.p256(.init())  // a fresh, unrelated key
            )
        }
    }

    @Test("signing outside the offered schemes is a typed error, not a wrong signature")
    func schemeMismatchFails() async throws {
        let authority = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(commonName: "server.test", by: authority)
        let identity = try TLSCertificateIdentity(
            certificateChainDER: [leaf.der], signer: TLSPrivateKey.p256(leaf.key)
        )
        await #expect(throws: TLSIdentityError.noCommonSignatureScheme(offered: [.ed25519])) {
            _ = try await identity.signature(over: [0], algorithms: [.ed25519])
        }
    }

    @Test("a garbage private-key PEM is a typed load error")
    func garbageKeyFails() {
        #expect(throws: TLSIdentityError.self) {
            _ = try TLSPrivateKey(pemRepresentation: "not pem at all")
        }
    }
}
