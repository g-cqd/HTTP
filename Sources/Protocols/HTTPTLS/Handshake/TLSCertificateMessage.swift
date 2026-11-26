//
//  TLSCertificateMessage.swift
//  HTTPTLS
//
//  RFC 8446 §4.4.2 — the Certificate message, both directions: the server's chain encoder
//  (X509 entries, per-entry extensions empty) and the client-authentication parser. The parser
//  enforces the §4.4.2 shape rules a server can check without a chain validator: the
//  `certificate_request_context` must echo ours (empty, §4.3.2), and Certificate-entry
//  extensions must correspond to our CertificateRequest — which offered none, so ANY entry
//  extension is `unsupported_extension` (§4.4.2). Chain VALIDATION is Phase 3c's; the DER
//  octets are surfaced untouched.
//

/// The Certificate message codec (RFC 8446 §4.4.2).
enum TLSCertificateCodec {
    /// Encodes the server Certificate: empty context, one `CertificateEntry` per DER
    /// certificate (leaf first), no entry extensions.
    static func certificate(chainDER: [[UInt8]]) -> [UInt8] {
        TLSHandshakeBuilder.message(.certificate) { message in
            message.vector8 { _ in
                // certificate_request_context: empty in the main handshake (§4.4.2)
            }
            message.vector24 { list in
                for certificate in chainDER {
                    list.vector24 { $0.raw(certificate) }  // cert_data
                    list.vector16 { _ in
                        // per-entry extensions: none (§4.4.2)
                    }
                }
            }
        }
    }

    /// Parses a client Certificate (§4.4.2) into its leaf-first DER chain.
    ///
    /// An EMPTY chain is a legal shape here ("a client that does not have a certificate...
    /// sends a Certificate message containing no certificates", §4.4.2) — the client-auth mode
    /// decides its fate in the machine. Entry extensions must answer our CertificateRequest,
    /// which offered none, so any is `unsupported_extension` (§6.2).
    static func parseClientCertificate(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) -> [[UInt8]] {
        try parseChain(message, permitsEntryExtensions: false)
    }

    /// Parses a server Certificate (§4.4.2): a non-empty leaf-first DER chain whose entries may
    /// carry the extensions our ClientHello solicited (`status_request`, SCTs) — tolerated, unused.
    static func parseServerCertificate(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) -> [[UInt8]] {
        let chain = try parseChain(message, permitsEntryExtensions: true)
        guard !chain.isEmpty else {
            throw .badCertificate("server sent an empty Certificate")
        }
        return chain
    }

    private static func parseChain(
        _ message: TLSHandshakeCoalescer.Message,
        permitsEntryExtensions: Bool
    ) throws(TLSHandshakeError) -> [[UInt8]] {
        var reader = TLSHandshakeReader(message.body)
        let context = try reader.vector8("certificate_request_context")
        guard context.isEmpty else {
            // §4.4.2: a handshake Certificate carries an empty context.
            throw .badCertificate("certificate_request_context not empty")
        }
        var chain: [[UInt8]] = []
        var list = TLSHandshakeReader(try reader.vector24("certificate_list"))
        while !list.isAtEnd {
            chain.append(try readEntry(&list, permitsEntryExtensions: permitsEntryExtensions))
        }
        try reader.expectEnd(of: "Certificate")
        return chain
    }

    /// One `CertificateEntry` (§4.4.2): non-empty `cert_data`, then its extensions block.
    private static func readEntry(
        _ list: inout TLSHandshakeReader,
        permitsEntryExtensions: Bool
    ) throws(TLSHandshakeError) -> [UInt8] {
        let certificate = try list.vector24("cert_data")
        guard !certificate.isEmpty else {
            throw .badCertificate("empty cert_data")  // §4.4.2 <1..2^24-1>
        }
        var extensions = TLSHandshakeReader(try list.vector16("certificate extensions"))
        if !permitsEntryExtensions, !extensions.isAtEnd {
            // §4.4.2: entry extensions must answer our CertificateRequest, which offered none —
            // so any extension here is unsupported_extension (§6.2).
            let type = TLSExtensionType(rawValue: try extensions.u16("extension type"))
            throw .unrequestedCertificateExtension(type)
        }
        return [UInt8](certificate)
    }
}
