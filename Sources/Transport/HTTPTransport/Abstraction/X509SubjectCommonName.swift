//
//  X509SubjectCommonName.swift
//  HTTPTransport
//
//  Extracts the subject Common Name (RFC 5280 §4.1.2.6, id-at-commonName 2.5.4.3) from a
//  DER-encoded X.509 certificate with the same minimal, bounds-checked TLV walk as
//  ``X509SubjectAlternativeNames`` — no ASN.1 library, no Security/OpenSSL dependency, one
//  implementation for every TLS backbone on every platform. Phase 3d's HTTPTLS-backed
//  portable engine uses it to surface `tlsPeerSubject` where the BoringSSL engine read
//  `X509_NAME_get_text_by_NID(..., NID_commonName, ...)` — the same answer for the same leaf.
//
//  The walk is strictly linear and non-recursive: Certificate SEQUENCE → TBSCertificate
//  SEQUENCE → (skip the optional [0] version and the INTEGER serial) → the 4th SEQUENCE
//  member is the subject Name (signature, issuer, validity precede it — RFC 5280 §4.1's
//  fixed field order) → RDNSequence → the first CN AttributeTypeAndValue. Anything
//  malformed returns nil (enrichment fails soft; the chain was already admitted by the
//  handshake's trust policy).
//
//  Standards: RFC 5280 §4.1 (TBSCertificate layout), §4.1.2.6 + X.520 (Name, CN);
//  ITU-T X.690 (DER TLV).
//

/// Extracts the subject CN from a DER-encoded X.509 certificate (RFC 5280 §4.1.2.6).
enum X509SubjectCommonName {
    /// The DER-encoded OID 2.5.4.3 (`id-at-commonName`) — contents only.
    private static let commonNameOID: [UInt8] = [0x55, 0x04, 0x03]

    /// The certificate's subject CN, or nil when it carries none (or the DER cannot be
    /// walked — never throws, never traps).
    static func extract(_ certificateDER: [UInt8]) -> String? {
        var reader = DERReader(certificateDER[...])
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }.
        guard let certificate = reader.readConstructed(tag: 0x30) else {
            return nil
        }
        var tbsReader = DERReader(certificate)
        guard let tbs = tbsReader.readConstructed(tag: 0x30) else {
            return nil
        }
        guard let subject = subjectName(in: tbs) else {
            return nil
        }
        return commonName(inSubject: subject)
    }

    /// The subject Name's RDNSequence contents: after the optional `[0] EXPLICIT version`
    /// and the INTEGER serial, the SEQUENCEs arrive in §4.1's fixed order — signature(1st),
    /// issuer(2nd), validity(3rd), subject(4th).
    private static func subjectName(in tbs: ArraySlice<UInt8>) -> ArraySlice<UInt8>? {
        var reader = DERReader(tbs)
        var sequencesSeen = 0
        while let element = reader.readElement() {
            guard element.tag == 0x30 else {
                continue  // [0] version, INTEGER serial — never a Name
            }
            sequencesSeen += 1
            if sequencesSeen == 4 {
                return element.content
            }
        }
        return nil
    }

    /// The first CN value in `RDNSequence ::= SEQUENCE OF SET OF AttributeTypeAndValue`.
    private static func commonName(inSubject subject: ArraySlice<UInt8>) -> String? {
        var rdnReader = DERReader(subject)
        while let set = rdnReader.readConstructed(tag: 0x31) {
            var attributeReader = DERReader(set)
            while let attribute = attributeReader.readConstructed(tag: 0x30) {
                var pairReader = DERReader(attribute)
                guard let oid = pairReader.readElement(), oid.tag == 0x06 else {
                    continue
                }
                guard Array(oid.content) == commonNameOID else {
                    continue
                }
                guard let value = pairReader.readElement() else {
                    return nil
                }
                return text(of: value)
            }
        }
        return nil
    }

    /// Decodes a DirectoryString value: UTF8String(0x0C), PrintableString(0x13),
    /// IA5String(0x16), or TeletexString(0x14) — the forms real CAs emit; BMP/Universal
    /// (UTF-16/32) are not decoded (nil, fail soft).
    private static func text(of element: DERReader.Element) -> String? {
        switch element.tag {
            case 0x0C, 0x13, 0x14, 0x16:
                String(validating: Array(element.content), as: UTF8.self)
            default:
                nil
        }
    }
}
