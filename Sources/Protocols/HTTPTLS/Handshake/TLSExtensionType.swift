//
//  TLSExtensionType.swift
//  HTTPTLS
//
//  RFC 8446 §4.2 — the `ExtensionType` registry, as a struct over the raw value (the
//  ``TLSAlertDescription`` pattern): §4.1.2 requires servers to IGNORE unrecognized ClientHello
//  extensions, so an unlisted value must survive parsing. §4.2's table is encoded here too: "if
//  an implementation receives an extension which it recognizes and which is not specified for
//  the message in which it appears, it MUST abort the handshake with an 'illegal_parameter'
//  alert" — for a server the only extension-bearing peer messages are ClientHello and the
//  client Certificate's entries, so the table collapses to ``isPermittedInClientHello``.
//

/// A TLS extension type (RFC 8446 §4.2; unknown values are preserved and ignored per §4.1.2).
public struct TLSExtensionType: RawRepresentable, Sendable, Equatable, Hashable {
    /// The wire value (§4.2's `ExtensionType`).
    public let rawValue: UInt16

    /// Wraps a raw extension-type value (unknown values are preserved per §4.1.2).
    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// `server_name(0)` (RFC 6066 §3; CH, EE).
    public static let serverName = Self(rawValue: 0)
    /// `max_fragment_length(1)` (RFC 6066 §4; CH, EE).
    public static let maxFragmentLength = Self(rawValue: 1)
    /// `status_request(5)` (RFC 6066 §8; CH, CR, CT).
    public static let statusRequest = Self(rawValue: 5)
    /// `supported_groups(10)` (§4.2.7; CH, EE).
    public static let supportedGroups = Self(rawValue: 10)
    /// `signature_algorithms(13)` (§4.2.3; CH, CR).
    public static let signatureAlgorithms = Self(rawValue: 13)
    /// `use_srtp(14)` (RFC 5764; CH, EE).
    public static let useSrtp = Self(rawValue: 14)
    /// `heartbeat(15)` (RFC 6520; CH, EE).
    public static let heartbeat = Self(rawValue: 15)
    /// `application_layer_protocol_negotiation(16)` (RFC 7301; CH, EE).
    public static let alpn = Self(rawValue: 16)
    /// `signed_certificate_timestamp(18)` (RFC 6962; CH, CR, CT).
    public static let signedCertificateTimestamp = Self(rawValue: 18)
    /// `client_certificate_type(19)` (RFC 7250; CH, EE).
    public static let clientCertificateType = Self(rawValue: 19)
    /// `server_certificate_type(20)` (RFC 7250; CH, EE).
    public static let serverCertificateType = Self(rawValue: 20)
    /// `padding(21)` (RFC 7685; CH only).
    public static let padding = Self(rawValue: 21)
    /// `record_size_limit(28)` (RFC 8449; CH, EE).
    public static let recordSizeLimit = Self(rawValue: 28)
    /// `session_ticket(35)` (RFC 5077 — the pre-1.3 mechanism; ignored, §4.2's table lists it
    /// for CH only via RFC 8447's registry note).
    public static let sessionTicket = Self(rawValue: 35)
    /// `pre_shared_key(41)` (§4.2.11; CH, SH) — MUST be the last ClientHello extension.
    public static let preSharedKey = Self(rawValue: 41)
    /// `early_data(42)` (§4.2.10; CH, EE, NST).
    public static let earlyData = Self(rawValue: 42)
    /// `supported_versions(43)` (§4.2.1; CH, SH, HRR).
    public static let supportedVersions = Self(rawValue: 43)
    /// `cookie(44)` (§4.2.2; CH, HRR).
    public static let cookie = Self(rawValue: 44)
    /// `psk_key_exchange_modes(45)` (§4.2.9; CH only).
    public static let pskKeyExchangeModes = Self(rawValue: 45)
    /// `certificate_authorities(47)` (§4.2.4; CH, CR).
    public static let certificateAuthorities = Self(rawValue: 47)
    /// `oid_filters(48)` (§4.2.5; CR ONLY — recognized in a ClientHello it is fatal, §4.2).
    public static let oidFilters = Self(rawValue: 48)
    /// `post_handshake_auth(49)` (§4.2.6; CH only).
    public static let postHandshakeAuth = Self(rawValue: 49)
    /// `signature_algorithms_cert(50)` (§4.2.3; CH, CR).
    public static let signatureAlgorithmsCert = Self(rawValue: 50)
    /// `key_share(51)` (§4.2.8; CH, SH, HRR).
    public static let keyShare = Self(rawValue: 51)

    /// The recognized types (the §4.2 table rows this implementation knows).
    private static let recognized: Set<UInt16> = [
        0, 1, 5, 10, 13, 14, 15, 16, 18, 19, 20, 21, 28, 35, 41, 42, 43, 44, 45, 47, 48, 49,
        50, 51
    ]

    /// Whether the §4.2 table knows this type at all (unrecognized ⇒ ignored per §4.1.2).
    public var isRecognized: Bool {
        Self.recognized.contains(rawValue)
    }

    /// Whether the §4.2 table permits this type in a ClientHello.
    ///
    /// Of the recognized types only `oid_filters` is barred from CH (it is CR-only); a
    /// recognized-but-barred type is fatal (`illegal_parameter`, §4.2).
    public var isPermittedInClientHello: Bool {
        isRecognized && self != .oidFilters
    }
}
