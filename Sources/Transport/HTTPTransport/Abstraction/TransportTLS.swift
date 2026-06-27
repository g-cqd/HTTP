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
    /// Whether the server requests a client certificate during the handshake (mutual TLS).
    ///
    /// ``none`` and ``required`` work on every TLS backbone. ``optional`` — request a certificate but
    /// proceed if the client presents none — requires the **portable TLS backbone**
    /// (``TransportBackbone/portableTLS``, `HTTP_PORTABLE_TLS`): Network.framework cannot model a
    /// request-but-don't-require handshake (the legacy `sec_protocol` flag is two-state, and the modern
    /// `NetworkListener<TLS>` deadlocks validating a presented client certificate — see ADR 0004), so
    /// it rejects ``optional`` with ``TransportError/unsupported(_:)`` rather than silently degrading.
    public enum ClientAuth: Sendable {
        /// One-way server TLS: no client certificate is requested (the default).
        case none
        /// Optional mutual TLS (RFC 8446 §4.4.2): the server *requests* a client certificate but the
        /// handshake still succeeds if the client presents none — ``TransportConnection/tlsPeerSubject``
        /// is then `nil`. A *presented* certificate is still run through ``verifyPeer`` (present-but-
        /// rejected fails the handshake). Requires the portable TLS backbone (see the type-level doc).
        case optional
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
    /// handshake when ``clientAuth`` is ``ClientAuth/required`` or ``ClientAuth/optional`` and the
    /// client presents a certificate.
    ///
    /// Receives the DER-encoded chain leaf-first (each element one certificate's raw bytes) and
    /// returns `false` to fail the handshake. Expressed over raw DER — not a backbone certificate type
    /// — so the policy is backbone-agnostic across the Network and portable TLS backbones. A `nil` hook
    /// accepts any chain the peer presents; presence is required under ``ClientAuth/required`` but
    /// optional under ``ClientAuth/optional`` (an absent certificate is allowed, a present one is still
    /// run through the hook).
    public var verifyPeer: (@Sendable ([[UInt8]]) -> Bool)?

    /// Per-server-name identities for SNI multi-cert selection (RFC 6066 §3): the handshake's
    /// `server_name` extension picks the matching identity; an unmatched name — or a client that sends
    /// no SNI — falls back to the default ``pkcs12``.
    ///
    /// Honored only by the portable TLS backbone (``TransportBackbone/portableTLS``); Network.framework
    /// exposes no server-side server-name callback. Empty by default (single-identity), so existing
    /// callers are unaffected.
    public var sniIdentities: [String: SNIIdentity]

    /// A PKCS#12 server identity bound to a server-name in ``sniIdentities`` (SNI multi-cert).
    public struct SNIIdentity: Sendable {
        /// A PKCS#12 (RFC 7292) blob holding this name's certificate chain and private key.
        public var pkcs12: [UInt8]
        /// The passphrase protecting ``pkcs12`` (empty if the blob is unencrypted).
        public var passphrase: String

        /// Creates an SNI identity from a PKCS#12 blob and its passphrase.
        public init(pkcs12: [UInt8], passphrase: String) {
            self.pkcs12 = pkcs12
            self.passphrase = passphrase
        }
    }

    /// Creates a TLS configuration from a PKCS#12 identity, the ALPN protocols to advertise, the TLS
    /// version range (default: TLS 1.3-only), the client-certificate policy (default: none), and an
    /// optional SNI multi-cert identity map (default: none).
    public init(
        pkcs12: [UInt8],
        passphrase: String,
        applicationProtocols: [String] = ["h2", "http/1.1"],
        minVersion: TLSVersion = .tlsV13,
        maxVersion: TLSVersion = .tlsV13,
        clientAuth: ClientAuth = .none,
        verifyPeer: (@Sendable ([[UInt8]]) -> Bool)? = nil,
        sniIdentities: [String: SNIIdentity] = [:]
    ) {
        self.pkcs12 = pkcs12
        self.passphrase = passphrase
        self.applicationProtocols = applicationProtocols
        self.minVersion = minVersion
        self.maxVersion = maxVersion
        self.clientAuth = clientAuth
        self.verifyPeer = verifyPeer
        self.sniIdentities = sniIdentities
    }
}
