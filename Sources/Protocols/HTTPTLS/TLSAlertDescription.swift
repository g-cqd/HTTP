//
//  TLSAlertDescription.swift
//  HTTPTLS
//
//  RFC 8446 §6 — the `AlertDescription` registry. A struct over the raw octet rather than an
//  enum (the HTTPStatus pattern): §6.2 requires unknown alert types to be *treated as* error
//  alerts, so an unlisted value must survive parsing and round-trip rather than fail it.
//

/// A TLS alert description octet (RFC 8446 §6).
public struct TLSAlertDescription: RawRepresentable, Sendable, Equatable, Hashable {
    /// The wire octet (RFC 8446 §6's `AlertDescription`).
    public let rawValue: UInt8

    /// Wraps a raw alert-description octet (unknown values are preserved per §6.2).
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// `close_notify(0)` — orderly closure of the write direction (§6.1).
    public static let closeNotify = Self(rawValue: 0)
    /// `unexpected_message(10)` — an inappropriate message was received (§6.2).
    public static let unexpectedMessage = Self(rawValue: 10)
    /// `bad_record_mac(20)` — a record failed deprotection; §5.2 folds every AEAD failure here.
    public static let badRecordMac = Self(rawValue: 20)
    /// `record_overflow(22)` — a record exceeded the §5.1/§5.2 length caps.
    public static let recordOverflow = Self(rawValue: 22)
    /// `handshake_failure(40)` — no acceptable set of security parameters (§6.2).
    public static let handshakeFailure = Self(rawValue: 40)
    /// `bad_certificate(42)` — a certificate was corrupt or otherwise unusable (§6.2).
    public static let badCertificate = Self(rawValue: 42)
    /// `unsupported_certificate(43)` — a certificate was of an unsupported type (§6.2).
    public static let unsupportedCertificate = Self(rawValue: 43)
    /// `certificate_expired(45)` — a certificate has expired or is not currently valid (§6.2).
    public static let certificateExpired = Self(rawValue: 45)
    /// `unknown_ca(48)` — the chain's CA could not be matched with a known trust anchor (§6.2).
    public static let unknownCA = Self(rawValue: 48)
    /// `illegal_parameter(47)` — a field was incorrect or inconsistent (§6.2).
    public static let illegalParameter = Self(rawValue: 47)
    /// `decode_error(50)` — a message could not be decoded (§6.2).
    public static let decodeError = Self(rawValue: 50)
    /// `decrypt_error(51)` — a handshake cryptographic operation failed (§6.2).
    public static let decryptError = Self(rawValue: 51)
    /// `protocol_version(70)` — the protocol version is not supported (§6.2).
    public static let protocolVersion = Self(rawValue: 70)
    /// `internal_error(80)` — a local failure unrelated to the peer (§6.2).
    public static let internalError = Self(rawValue: 80)
    /// `user_canceled(90)` — cancellation for a reason outside a protocol failure (§6.1).
    public static let userCanceled = Self(rawValue: 90)
    /// `missing_extension(109)` — a mandatory extension was absent (§6.2).
    public static let missingExtension = Self(rawValue: 109)
    /// `unsupported_extension(110)` — an extension appeared where prohibited (§6.2).
    public static let unsupportedExtension = Self(rawValue: 110)
    /// `unrecognized_name(112)` — no server exists identified by the client's SNI (§6.2).
    public static let unrecognizedName = Self(rawValue: 112)
    /// `certificate_required(116)` — a required client certificate was absent (§4.4.2.4/§6.2).
    public static let certificateRequired = Self(rawValue: 116)
    /// `no_application_protocol(120)` — ALPN offered no protocol the server supports (RFC 7301).
    public static let noApplicationProtocol = Self(rawValue: 120)
}
