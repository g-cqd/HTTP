//
//  TransportTLS.swift
//  HTTPTransport
//
//  The switchable backbone flag, its configuration, and transport errors.
//

/// TLS server configuration for a backbone that supports it (Network.framework).
///
/// Expressed in backbone-agnostic terms — a PKCS#12 (RFC 7292) identity blob and the ALPN protocol
/// list (RFC 7301) — so the Abstraction layer never imports Security/Network. The Network backbone
/// turns this into a `sec_identity_t` and `NWProtocolTLS.Options`. Advertising `"h2"` is what lets a
/// client negotiate HTTP/2 over TLS (RFC 9113 §3.3); cleartext backbones ignore this.
public struct TransportTLS: Sendable {
    /// A PKCS#12 (RFC 7292) blob holding the server certificate chain and its private key.
    public var pkcs12: [UInt8]

    /// The passphrase protecting ``pkcs12`` (empty if the blob is unencrypted).
    public var passphrase: String

    /// ALPN protocols to offer, most-preferred first (RFC 7301) — e.g. `["h2", "http/1.1"]`.
    public var applicationProtocols: [String]

    /// The lowest TLS version to negotiate (RFC 9325 / BCP 195).
    ///
    /// Defaults to TLS 1.3.
    public var minVersion: TLSVersion

    /// The highest TLS version to negotiate.
    ///
    /// Defaults to TLS 1.3, pinning the ceiling (audit T-F5) so a future platform draft version
    /// cannot be negotiated unintentionally.
    public var maxVersion: TLSVersion

    /// Creates a TLS configuration from a PKCS#12 identity, the ALPN protocols to advertise, and the
    /// TLS version range (default: TLS 1.3-only).
    public init(
        pkcs12: [UInt8],
        passphrase: String,
        applicationProtocols: [String] = ["h2", "http/1.1"],
        minVersion: TLSVersion = .tlsV13,
        maxVersion: TLSVersion = .tlsV13
    ) {
        self.pkcs12 = pkcs12
        self.passphrase = passphrase
        self.applicationProtocols = applicationProtocols
        self.minVersion = minVersion
        self.maxVersion = maxVersion
    }
}
