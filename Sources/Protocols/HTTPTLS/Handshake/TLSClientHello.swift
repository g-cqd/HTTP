//
//  TLSClientHello.swift
//  HTTPTLS
//
//  RFC 8446 §4.1.2 — the parsed ClientHello. Parsing enforces exactly the §4.1.2/§4.2 shape
//  rules that are position-dependent (and therefore lost after parsing): the fixed fields'
//  bounds, the extension block's framing, §4.2's no-duplicates rule, §4.2's
//  recognized-but-not-permitted rule, and §4.2.11's pre_shared_key-must-be-last rule.
//  VALUE rules (versions, compression, share lengths, limits) belong to the machine, which
//  knows the negotiation context. Unrecognized extensions are skipped whole (§4.1.2: "Servers
//  MUST ignore unrecognized extensions").
//

/// A parsed ClientHello (RFC 8446 §4.1.2) — fields nil when the extension was absent.
struct TLSClientHello: Sendable, Equatable {
    /// `legacy_version` — ignored for negotiation when `supported_versions` is present
    /// (§4.2.1), but 0x0300 or less is fatal (Appendix D.5).
    var legacyVersion: UInt16 = 0
    /// The 32-octet client `random` (§4.1.2).
    var random: [UInt8] = []
    /// `legacy_session_id` (0..32 octets) — echoed verbatim in ServerHello (§4.1.3).
    var legacySessionID: [UInt8] = []
    /// The offered cipher suites, raw and in client order (§4.1.2).
    var cipherSuites: [UInt16] = []
    /// `legacy_compression_methods` — must be exactly [0] for TLS 1.3 (§4.1.2).
    var compressionMethods: [UInt8] = []
    /// The SNI host name (RFC 6066 §3), when offered.
    var serverName: String?
    /// `supported_groups` (§4.2.7), client preference order.
    var supportedGroups: [TLSNamedGroup]?
    /// `signature_algorithms` (§4.2.3).
    var signatureAlgorithms: [TLSSignatureScheme]?
    /// `signature_algorithms_cert` (§4.2.3), when the client separates certificate schemes.
    var signatureAlgorithmsCert: [TLSSignatureScheme]?
    /// ALPN protocol names (RFC 7301 §3.1), client preference order.
    var alpnProtocols: [String]?
    /// `supported_versions` (§4.2.1) — absence means the client is pre-1.3 (Appendix D.2).
    var supportedVersions: [UInt16]?
    /// `key_share` entries (§4.2.8) — an EMPTY list is legal and requests HRR group selection.
    var keyShares: [TLSKeyShareEntry]?
    /// `psk_key_exchange_modes` (§4.2.9) — mandatory alongside `pre_shared_key`.
    var pskKeyExchangeModes: [UInt8]?
    /// The `pre_shared_key` offer (§4.2.11), always the last extension when present.
    var preSharedKey: TLSPreSharedKeyOffer?
    /// Whether `early_data` was offered (§4.2.10) — this server always declines it.
    var offeredEarlyData = false
    /// The echoed HRR `cookie` (§4.2.2), when present.
    var cookie: [UInt8]?
    /// `record_size_limit` (RFC 8449) — the peer's receive limit, noted and honored outbound.
    var recordSizeLimit: Int?

    /// The §4.2.9 `psk_dhe_ke(1)` mode octet — the only mode this server accepts.
    static let pskDheKeMode: UInt8 = 1

    /// Parses a reassembled ClientHello message.
    static func parse(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) -> Self {
        var hello = Self()
        var reader = TLSHandshakeReader(message.body)
        hello.legacyVersion = try reader.u16("legacy_version")
        hello.random = [UInt8](try reader.slice(32, "random"))
        hello.legacySessionID = [UInt8](try reader.vector8("legacy_session_id"))
        guard hello.legacySessionID.count <= 32 else {
            throw .malformed("legacy_session_id longer than 32")  // §4.1.2 <0..32>
        }
        hello.cipherSuites = try reader.u16List("cipher_suites")
        guard !hello.cipherSuites.isEmpty else {
            throw .malformed("cipher_suites empty")  // §4.1.2 <2..2^16-2>
        }
        hello.compressionMethods = [UInt8](try reader.vector8("legacy_compression_methods"))
        guard !hello.compressionMethods.isEmpty else {
            throw .malformed("legacy_compression_methods empty")  // §4.1.2 <1..2^8-1>
        }
        try hello.parseExtensions(&reader)
        try reader.expectEnd(of: "ClientHello")
        return hello
    }

    /// Walks the extension block, enforcing §4.2's positional rules and dispatching each
    /// recognized extension to its field parser.
    private mutating func parseExtensions(
        _ reader: inout TLSHandshakeReader
    ) throws(TLSHandshakeError) {
        let block = try reader.vector16("extensions")
        var cursor = TLSHandshakeReader(block)
        var seen = Set<TLSExtensionType>()
        while !cursor.isAtEnd {
            if preSharedKey != nil {
                throw .preSharedKeyNotLast  // §4.2.11: MUST be the last extension
            }
            let type = TLSExtensionType(rawValue: try cursor.u16("extension type"))
            let data = try cursor.vector16("extension data")
            guard type.isRecognized else {
                continue  // §4.1.2: servers MUST ignore unrecognized extensions
            }
            guard type.isPermittedInClientHello else {
                throw .extensionNotPermitted(type)  // §4.2's table
            }
            guard seen.insert(type).inserted else {
                throw .duplicateExtension(type)  // §4.2: at most one of each type
            }
            try applyExtension(type, data: data)
        }
    }
}
