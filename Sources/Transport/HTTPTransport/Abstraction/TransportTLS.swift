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
    /// Whether the server requires a client certificate during the handshake (mutual TLS).
    ///
    /// Network.framework cleanly supports only require-or-none, so ``optional`` is intentionally
    /// absent until the portable BoringSSL path (G0) can model a request-but-don't-require handshake.
    public enum ClientAuth: Sendable {
        /// One-way server TLS: no client certificate is requested (the default).
        case none
        /// Mutual TLS (RFC 8446 §4.4.2): the client must present a certificate and the handshake
        /// fails if it does not, or if ``verifyPeer`` rejects the presented chain.
        case required
    }

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

    /// The client-certificate policy (mutual TLS).
    ///
    /// Defaults to ``ClientAuth/none`` (one-way TLS).
    public var clientAuth: ClientAuth

    /// An optional trust / pinning hook over the client's certificate chain, evaluated during the
    /// handshake when ``clientAuth`` is ``ClientAuth/required``.
    ///
    /// Receives the DER-encoded chain leaf-first (each element one certificate's raw bytes) and
    /// returns `false` to fail the handshake. Expressed over raw DER — not a backbone certificate
    /// type — so the policy is backbone-agnostic and portable to the future BoringSSL path (G0). A
    /// `nil` hook accepts any chain the peer presents (presence is still required under
    /// ``ClientAuth/required``).
    public var verifyPeer: (@Sendable ([[UInt8]]) -> Bool)?

    /// Creates a TLS configuration from a PKCS#12 identity, the ALPN protocols to advertise, the TLS
    /// version range (default: TLS 1.3-only), and the client-certificate policy (default: none).
    public init(
        pkcs12: [UInt8],
        passphrase: String,
        applicationProtocols: [String] = ["h2", "http/1.1"],
        minVersion: TLSVersion = .tlsV13,
        maxVersion: TLSVersion = .tlsV13,
        clientAuth: ClientAuth = .none,
        verifyPeer: (@Sendable ([[UInt8]]) -> Bool)? = nil
    ) {
        self.pkcs12 = pkcs12
        self.passphrase = passphrase
        self.applicationProtocols = applicationProtocols
        self.minVersion = minVersion
        self.maxVersion = maxVersion
        self.clientAuth = clientAuth
        self.verifyPeer = verifyPeer
    }
}
