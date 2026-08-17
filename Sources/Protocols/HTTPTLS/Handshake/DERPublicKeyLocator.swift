//
//  DERPublicKeyLocator.swift
//  HTTPTLS
//
//  A minimal DER TLV walk that locates the SubjectPublicKeyInfo inside an X.509 certificate
//  (RFC 5280 §4.1: Certificate → TBSCertificate → the field after subject) — just enough for
//  §4.4.3 CertificateVerify verification against the presented leaf. This is STRUCTURE walking,
//  not certificate validation (no signatures, no names, no chains — all Phase 3c via
//  swift-certificates) and not a crypto primitive: swift-crypto's key initializers consume the
//  located SPKI. Definite lengths only, as DER requires (X.690 §10.1).
//

/// Locates the SubjectPublicKeyInfo TLV inside a DER X.509 certificate (RFC 5280 §4.1).
enum DERPublicKeyLocator {
    /// One DER TLV: its tag and content slice.
    private struct TLV {
        /// The tag octet (identifier; multi-octet tags never occur in RFC 5280 §4.1's spine).
        let tag: UInt8
        /// The content octets.
        let content: ArraySlice<UInt8>
        /// Where the TLV's octets end in the underlying buffer.
        let end: Int
    }

    /// Returns the complete SubjectPublicKeyInfo TLV (RFC 5280 §4.1.2.7) from a certificate.
    static func subjectPublicKeyInfo(
        inCertificateDER der: [UInt8]
    ) throws(TLSHandshakeError) -> [UInt8] {
        let certificate = try read(der[...], expecting: 0x30, "Certificate")  // SEQUENCE
        let tbs = try read(certificate.content, expecting: 0x30, "TBSCertificate")
        var cursor = tbs.content
        // RFC 5280 §4.1: [0] version (optional) — serialNumber — signature — issuer —
        // validity — subject — subjectPublicKeyInfo.
        if cursor.first == 0xA0 {
            cursor = try skip(cursor, "version")
        }
        cursor = try skip(cursor, "serialNumber")
        cursor = try skip(cursor, "signature")
        cursor = try skip(cursor, "issuer")
        cursor = try skip(cursor, "validity")
        cursor = try skip(cursor, "subject")
        let start = cursor.startIndex
        let spki = try read(cursor, expecting: 0x30, "subjectPublicKeyInfo")
        return [UInt8](der[start ..< spki.end])
    }

    /// Extracts the raw subject public key BITS from an SPKI — the BIT STRING's content with
    /// its unused-bits octet stripped (RFC 5280 §4.1.2.7).
    ///
    /// Ed25519's raw key comes from here (RFC 8410 §4); EC keys go to swift-crypto as the
    /// whole SPKI instead.
    static func rawSubjectPublicKey(
        inSubjectPublicKeyInfoDER spki: [UInt8]
    ) throws(TLSHandshakeError) -> [UInt8] {
        let outer = try read(spki[...], expecting: 0x30, "SubjectPublicKeyInfo")
        let afterAlgorithm = try skip(outer.content, "algorithm")
        let bitString = try read(afterAlgorithm, expecting: 0x03, "subjectPublicKey")
        guard let unusedBits = bitString.content.first, unusedBits == 0 else {
            throw .badCertificate("subjectPublicKey unused bits")  // keys are octet-aligned
        }
        return [UInt8](bitString.content.dropFirst())
    }

    /// Reads the TLV at the cursor's head, requiring `tag`.
    private static func read(
        _ bytes: ArraySlice<UInt8>, expecting tag: UInt8, _ label: String
    ) throws(TLSHandshakeError) -> TLV {
        let tlv = try tlv(at: bytes, label)
        guard tlv.tag == tag else {
            throw .badCertificate("\(label): unexpected tag \(tlv.tag)")
        }
        return tlv
    }

    /// Skips one TLV, returning the remainder.
    private static func skip(
        _ bytes: ArraySlice<UInt8>, _ label: String
    ) throws(TLSHandshakeError) -> ArraySlice<UInt8> {
        let tlv = try tlv(at: bytes, label)
        return bytes[tlv.end...]
    }

    /// Decodes one TLV header + content (definite lengths only, X.690 §10.1; length of length
    /// capped at 4 octets — a 2^32-octet certificate is not a certificate).
    private static func tlv(
        at bytes: ArraySlice<UInt8>, _ label: String
    ) throws(TLSHandshakeError) -> TLV {
        var index = bytes.startIndex
        guard bytes.endIndex - index >= 2 else {
            throw .badCertificate("\(label): truncated TLV")
        }
        let tag = bytes[index]
        index += 1
        var length = Int(bytes[index])
        index += 1
        if length >= 0x80 {
            let lengthOfLength = length & 0x7F
            guard lengthOfLength >= 1, lengthOfLength <= 4,
                bytes.endIndex - index >= lengthOfLength
            else {
                throw .badCertificate("\(label): bad length of length")
            }
            length = 0
            for _ in 0 ..< lengthOfLength {
                length = length << 8 | Int(bytes[index])
                index += 1
            }
        }
        guard bytes.endIndex - index >= length else {
            throw .badCertificate("\(label): truncated content")
        }
        return TLV(tag: tag, content: bytes[index ..< index + length], end: index + length)
    }
}
