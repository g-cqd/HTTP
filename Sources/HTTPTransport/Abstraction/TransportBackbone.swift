//
//  TransportBackbone.swift
//  HTTPTransport
//
//  The switchable backbone flag, its configuration, and transport errors.
//

/// Selects which transport implementation to wire (chosen at composition time).
public enum TransportBackbone: String, Sendable, CaseIterable {

    /// Apple Network.framework (`NWListener` / `NWConnection`) — TLS, ALPN, and QUIC.
    case networkFramework

    /// BSD sockets with a hand-rolled kqueue readiness loop — closest to the hardware.
    case posixKqueue

    /// BSD sockets with GCD `DispatchSource` readiness (kqueue under the hood, less hand-rolled).
    case posixDispatch

    /// apple/swift-system typed descriptor wrappers over the POSIX socket syscalls.
    case swiftSystem

    /// In-memory transport for deterministic tests (no sockets).
    case fake
}

/// Configuration for binding a ``ServerTransport``.
public struct TransportConfiguration: Sendable {

    /// The host / interface to bind (default loopback).
    public var host: String

    /// The port to bind (`0` selects an ephemeral port).
    public var port: UInt16

    /// Which backbone to instantiate.
    public var backbone: TransportBackbone

    /// TLS configuration, or `nil` for a cleartext listener (h1 / h2c).
    ///
    /// Honored only by a TLS-capable backbone (``TransportBackbone/networkFramework``); the POSIX and
    /// fake backbones are cleartext and ignore it.
    public var tls: TransportTLS?

    /// Creates a transport configuration.
    public init(
        host: String = "127.0.0.1",
        port: UInt16,
        backbone: TransportBackbone,
        tls: TransportTLS? = nil
    ) {
        self.host = host
        self.port = port
        self.backbone = backbone
        self.tls = tls
    }
}

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

    /// Creates a TLS configuration from a PKCS#12 identity and the ALPN protocols to advertise.
    public init(
        pkcs12: [UInt8],
        passphrase: String,
        applicationProtocols: [String] = ["h2", "http/1.1"]
    ) {
        self.pkcs12 = pkcs12
        self.passphrase = passphrase
        self.applicationProtocols = applicationProtocols
    }
}

/// Errors raised by a transport backbone.
public enum TransportError: Error, Sendable, Equatable {

    /// This backbone is not yet implemented.
    case notImplemented(TransportBackbone)

    /// Binding or starting the listener failed, with a diagnostic message.
    case bindFailed(String)

    /// A read or write on a connection failed, with a diagnostic message.
    case ioFailed(String)

    /// Building the TLS context failed (bad PKCS#12, wrong passphrase, missing identity).
    case tlsConfigurationFailed(String)

    /// The connection or listener has already been closed.
    case closed
}
