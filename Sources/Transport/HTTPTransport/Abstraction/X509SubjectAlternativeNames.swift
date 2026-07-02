//
//  X509SubjectAlternativeNames.swift
//  HTTPTransport
//
//  Extracts the Subject Alternative Name entries (RFC 5280 §4.2.1.6) from a DER-encoded X.509
//  certificate (X.690 DER) with a minimal, bounds-checked TLV walk — no ASN.1 library, no
//  Security/OpenSSL dependency, so one implementation serves every TLS backbone (Network, portable,
//  QUIC) on every platform. Runs once per handshake, never on the byte path.
//
//  The walk is strictly linear and non-recursive: outer Certificate SEQUENCE → TBSCertificate
//  SEQUENCE → the [3] EXPLICIT Extensions member → the SAN extension (OID 2.5.29.17) → its
//  GeneralNames. Anything malformed, truncated, or out of spec makes the extractor return what it
//  has (never trap, never over-read) — the certificate was already admitted by the handshake's
//  verifyPeer policy; SAN extraction is context enrichment, not validation.
//
//  Standards: RFC 5280 §4.1 (Certificate/TBSCertificate layout), §4.2.1.6 (SubjectAltName,
//  GeneralName tags); ITU-T X.690 (DER TLV encoding); RFC 791 / RFC 4291 §2.2 (address text forms).
//

/// Extracts Subject Alternative Names from a DER-encoded X.509 certificate (RFC 5280 §4.2.1.6).
enum X509SubjectAlternativeNames {
    /// The DER-encoded OID 2.5.29.17 (`id-ce-subjectAltName`, RFC 5280 §4.2.1.6) — contents only.
    private static let subjectAltNameOID: [UInt8] = [0x55, 0x1D, 0x11]

    /// The SAN entries of `certificateDER`, or `[]` when the certificate carries none (or the DER
    /// cannot be walked — enrichment fails soft, it never throws).
    static func extract(_ certificateDER: [UInt8]) -> [SubjectAlternativeName] {
        var reader = DERReader(certificateDER[...])
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } (§4.1).
        guard let certificate = reader.readConstructed(tag: 0x30) else {
            return []
        }
        var tbsReader = DERReader(certificate)
        // TBSCertificate ::= SEQUENCE { ... extensions [3] EXPLICIT Extensions OPTIONAL } (§4.1).
        guard let tbs = tbsReader.readConstructed(tag: 0x30) else {
            return []
        }
        guard let extensions = extensionsMember(in: tbs) else {
            return []
        }
        return subjectAltNames(inExtensions: extensions)
    }

    /// The contents of the TBSCertificate's `[3] EXPLICIT Extensions` member: skip the leading
    /// members (their tags never collide with `0xA3`), then unwrap the explicit tag down to the
    /// `SEQUENCE OF Extension` contents.
    private static func extensionsMember(in tbs: ArraySlice<UInt8>) -> ArraySlice<UInt8>? {
        var reader = DERReader(tbs)
        while let element = reader.readElement() {
            guard element.tag == 0xA3 else {
                continue  // version/serial/signature/issuer/validity/subject/SPKI/uniqueIDs
            }
            var explicitReader = DERReader(element.content)
            return explicitReader.readConstructed(tag: 0x30)
        }
        return nil
    }

    /// Finds the SAN extension in `Extensions ::= SEQUENCE OF Extension` and decodes its names.
    ///
    /// `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`.
    private static func subjectAltNames(
        inExtensions extensions: ArraySlice<UInt8>
    ) -> [SubjectAlternativeName] {
        var reader = DERReader(extensions)
        while let contents = reader.readConstructed(tag: 0x30) {
            var extensionReader = DERReader(contents)
            guard let oid = extensionReader.readElement(), oid.tag == 0x06 else {
                continue
            }
            guard Array(oid.content) == subjectAltNameOID else {
                continue
            }
            // Skip the optional `critical BOOLEAN` to reach the OCTET STRING value.
            guard var value = extensionReader.readElement() else {
                return []
            }
            if value.tag == 0x01 {
                guard let octets = extensionReader.readElement() else {
                    return []
                }
                value = octets
            }
            guard value.tag == 0x04 else {
                return []
            }
            var namesReader = DERReader(value.content)
            guard let names = namesReader.readConstructed(tag: 0x30) else {
                return []
            }
            return generalNames(names)
        }
        return []
    }

    /// Decodes `GeneralNames ::= SEQUENCE OF GeneralName`, keeping the four network-peer forms:
    /// `rfc822Name [1]`, `dNSName [2]`, `uniformResourceIdentifier [6]` (IA5Strings) and
    /// `iPAddress [7]` (an OCTET STRING of 4 or 16 octets) — RFC 5280 §4.2.1.6.
    private static func generalNames(_ contents: ArraySlice<UInt8>) -> [SubjectAlternativeName] {
        var reader = DERReader(contents)
        var names: [SubjectAlternativeName] = []
        while let element = reader.readElement() {
            switch element.tag {
                case 0x81:
                    names.append(.email(String(decoding: element.content, as: Unicode.UTF8.self)))
                case 0x82:
                    names.append(.dns(String(decoding: element.content, as: Unicode.UTF8.self)))
                case 0x86:
                    names.append(.uri(String(decoding: element.content, as: Unicode.UTF8.self)))
                case 0x87:
                    if let address = ipText(Array(element.content)) {
                        names.append(.ip(address))
                    }
                default:
                    continue  // otherName/x400/directoryName/ediParty/registeredID — skipped
            }
        }
        return names
    }

    /// Renders a 4-octet address as dotted quad (RFC 791) or a 16-octet one as full colon-grouped
    /// IPv6 (RFC 4291 §2.2 form 1, no zero compression); other lengths are malformed → `nil`.
    private static func ipText(_ octets: [UInt8]) -> String? {
        if octets.count == 4 {
            return octets.map(String.init).joined(separator: ".")
        }
        guard octets.count == 16 else {
            return nil
        }
        var groups: [String] = []
        for index in stride(from: 0, to: 16, by: 2) {
            let group = UInt16(octets[index]) << 8 | UInt16(octets[index + 1])
            groups.append(String(group, radix: 16))
        }
        return groups.joined(separator: ":")
    }
}
