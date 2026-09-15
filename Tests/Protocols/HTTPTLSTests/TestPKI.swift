//
//  TestPKI.swift
//  HTTPTLSTests
//
//  A miniature PKI minted with swift-certificates' own builders (no `openssl` shelling —
//  the 3c gate): a P-256 root CA, an optional intermediate, and leaves with configurable
//  validity windows and SANs. P-256 keys throughout — the fastest of the supported
//  families, and one suite exercises every 3c path (RSA parity has its own openssl-minted
//  fixture, which is the point of that test).
//

import Crypto
import Foundation
import SwiftASN1
import Synchronization
import X509

@testable internal import HTTPTLS

/// Mints in-memory test certificates and chains (test-only).
enum TestPKI {
    // Test certificates need unique serials. Avoid the upstream random initializer's TSan crash.
    private static let serialSequence = Atomic<UInt64>(0)

    private static func nextSerialNumber() -> Certificate.SerialNumber {
        Certificate.SerialNumber(serialSequence.wrappingAdd(1, ordering: .relaxed).oldValue + 1)
    }

    /// One certificate + its P-256 key, in every form the 3c intake reads.
    struct Entity {
        let certificate: Certificate
        let key: P256.Signing.PrivateKey

        /// The DER form (RFC 5280).
        var der: [UInt8] {
            (try? Self.serialize(certificate)) ?? []
        }

        /// The PEM form (RFC 7468).
        var pem: String {
            (try? certificate.serializeAsPEM().pemString) ?? ""
        }

        /// The key's PKCS#8 PEM (RFC 5958).
        var keyPEM: String {
            key.pemRepresentation
        }

        private static func serialize(_ certificate: Certificate) throws -> [UInt8] {
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            return serializer.serializedBytes
        }
    }

    /// A self-signed CA (`basicConstraints CA:TRUE`, RFC 5280 §4.2.1.9).
    static func certificateAuthority(
        commonName: String = "HTTPTLS Test CA"
    ) throws -> Entity {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName(commonName) }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: nextSerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: Date().addingTimeInterval(-3_600),
            notValidAfter: Date().addingTimeInterval(86_400),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
            },
            issuerPrivateKey: Certificate.PrivateKey(key)
        )
        return Entity(certificate: certificate, key: key)
    }

    /// A certificate issued by `issuer` — a leaf by default; an intermediate CA when
    /// `isAuthority`; expired/not-yet-valid via the validity offsets (seconds from now).
    static func issued(
        commonName: String,
        by issuer: Entity,
        isAuthority: Bool = false,
        sans: [String] = [],
        notValidBeforeOffset: TimeInterval = -3_600,
        notValidAfterOffset: TimeInterval = 86_400
    ) throws -> Entity {
        let key = P256.Signing.PrivateKey()
        let certificate = try Certificate(
            version: .v3,
            serialNumber: nextSerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: Date().addingTimeInterval(notValidBeforeOffset),
            notValidAfter: Date().addingTimeInterval(notValidAfterOffset),
            issuer: issuer.certificate.subject,
            subject: try DistinguishedName { CommonName(commonName) },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                if isAuthority {
                    Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                }
                if !sans.isEmpty {
                    SubjectAlternativeNames(sans.map { GeneralName.dnsName($0) })
                }
            },
            issuerPrivateKey: Certificate.PrivateKey(issuer.key)
        )
        return Entity(certificate: certificate, key: key)
    }

    /// An Ed25519 self-signed identity (leaf + PKCS#8 key PEM) — the RFC 8410 intake path.
    static func ed25519SelfSigned(
        commonName: String = "ed25519.test"
    ) throws -> (certificatePEM: String, keyPEM: String, key: Curve25519.Signing.PrivateKey) {
        let key = Curve25519.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName(commonName) }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: nextSerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: Date().addingTimeInterval(-3_600),
            notValidAfter: Date().addingTimeInterval(86_400),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ed25519,
            extensions: Certificate.Extensions(),
            issuerPrivateKey: Certificate.PrivateKey(key)
        )
        return (
            certificatePEM: try certificate.serializeAsPEM().pemString,
            keyPEM: try Certificate.PrivateKey(key).serializeAsPEM().pemString,
            key: key
        )
    }
}
