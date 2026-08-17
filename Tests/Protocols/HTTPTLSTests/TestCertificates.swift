//
//  TestCertificates.swift
//  HTTPTLSTests
//
//  A minimal DER X.509 shell around a real SubjectPublicKeyInfo — just enough structure for
//  ``DERPublicKeyLocator``'s RFC 5280 §4.1 walk (serial, algorithm, empty issuer/validity/
//  subject, then the SPKI) plus a dummy outer signature. Chain VALIDATION is Phase 3c's;
//  Phase 3b only needs a leaf whose public key is real, so the CertificateVerify signature
//  check exercises genuine swift-crypto verification.
//

/// Builds throwaway DER certificates around real public keys (test-only).
enum TestCertificates {
    /// Wraps an SPKI in a minimal certificate: SEQ{ tbs, sigAlg, BIT STRING 0 }.
    static func certificate(aroundSubjectPublicKeyInfo spki: [UInt8]) -> [UInt8] {
        // ecdsa-with-SHA256 (1.2.840.10045.4.3.2) — the value is irrelevant to the walk.
        let algorithm = sequence([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])
        var tbs: [UInt8] = []
        tbs += [0x02, 0x01, 0x01]  // serialNumber INTEGER 1
        tbs += algorithm  // signature
        tbs += sequence([])  // issuer (empty RDNSequence)
        tbs += sequence([])  // validity (structurally empty — never validated here)
        tbs += sequence([])  // subject
        tbs += spki  // subjectPublicKeyInfo — the one REAL field
        var certificate = sequence(tbs)
        certificate += algorithm  // signatureAlgorithm
        certificate += [0x03, 0x02, 0x00, 0x00]  // signatureValue BIT STRING (dummy)
        return sequence(certificate)
    }

    /// DER SEQUENCE around `content` (definite length, long form when needed).
    private static func sequence(_ content: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [0x30]
        if content.count < 0x80 {
            out.append(UInt8(truncatingIfNeeded: content.count))
        }
        else if content.count <= 0xFF {
            out.append(0x81)
            out.append(UInt8(truncatingIfNeeded: content.count))
        }
        else {
            out.append(0x82)
            out.append(UInt8(truncatingIfNeeded: content.count >> 8))
            out.append(UInt8(truncatingIfNeeded: content.count))
        }
        out += content
        return out
    }
}
