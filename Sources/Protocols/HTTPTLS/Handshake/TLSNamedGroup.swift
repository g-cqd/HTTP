//
//  TLSNamedGroup.swift
//  HTTPTLS
//
//  RFC 8446 §4.2.7 — the `NamedGroup` registry. A struct over the raw value: a ClientHello may
//  legitimately offer groups this server does not implement (they are skipped during
//  negotiation, never a parse failure), and the §4.2.7 EncryptedExtensions hint may name groups
//  beyond the implemented set. The implemented key-exchange groups are exactly the two the
//  scope fixes: X25519 (RFC 7748) and secp256r1 (P-256), both via swift-crypto.
//

/// A TLS named group (RFC 8446 §4.2.7; unknown values are preserved for negotiation/hints).
public struct TLSNamedGroup: RawRepresentable, Sendable, Equatable, Hashable {
    /// The wire value (§4.2.7's `NamedGroup`).
    public let rawValue: UInt16

    /// Wraps a raw named-group value (unimplemented values survive parsing per §4.1.2).
    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// `secp256r1(0x0017)` — NIST P-256 (§4.2.7), via swift-crypto `P256.KeyAgreement`.
    public static let secp256r1 = Self(rawValue: 0x0017)
    /// `secp384r1(0x0018)` (§4.2.7) — recognized, not implemented for key exchange.
    public static let secp384r1 = Self(rawValue: 0x0018)
    /// `secp521r1(0x0019)` (§4.2.7) — recognized, not implemented for key exchange.
    public static let secp521r1 = Self(rawValue: 0x0019)
    /// `x25519(0x001D)` (RFC 7748, §4.2.7), via swift-crypto `Curve25519.KeyAgreement`.
    public static let x25519 = Self(rawValue: 0x001D)
    /// `x448(0x001E)` (§4.2.7) — recognized, not implemented for key exchange.
    public static let x448 = Self(rawValue: 0x001E)
    /// `ffdhe2048(0x0100)` (RFC 7919, §4.2.7) — recognized, not implemented.
    public static let ffdhe2048 = Self(rawValue: 0x0100)

    /// Whether this server can run the group's key exchange (X25519 + P-256, swift-crypto).
    public var isImplemented: Bool {
        self == .x25519 || self == .secp256r1
    }

    /// The §4.2.8.2 length of a `KeyShareEntry.key_exchange` for this group, or nil when the
    /// group is not implemented (X25519: 32 raw octets; P-256: 65 uncompressed X9.62 octets).
    public var keyExchangeLength: Int? {
        switch self {
            case .x25519:
                32
            case .secp256r1:
                65
            default:
                nil
        }
    }
}
