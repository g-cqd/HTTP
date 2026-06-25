//
//  TransportConfiguration.swift
//  HTTPTransport
//
//  The switchable backbone flag, its configuration, and transport errors.
//

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

    /// Whether to bind the listen socket with `SO_REUSEPORT` (POSIX backbones only).
    ///
    /// Set by a prefork worker so N workers can share the port and the kernel load-balances accepts
    /// across them. Off by default — see ``POSIXSocket/makeListenSocket(host:port:nonBlocking:reusePort:)``.
    public var reusePort: Bool

    /// The `listen()` backlog — the kernel's pending-connection queue depth (POSIX backbones only).
    ///
    /// Default 256; the OS clamps it to its own maximum (`kern.ipc.somaxconn`), so raising that sysctl
    /// lets a higher value take effect. Replaces a previously hard-coded `128` (audit T-F14).
    public var backlog: Int32

    /// Creates a transport configuration.
    public init(
        host: String = "127.0.0.1",
        port: UInt16,
        backbone: TransportBackbone,
        tls: TransportTLS? = nil,
        reusePort: Bool = false,
        backlog: Int32 = 256
    ) {
        self.host = host
        self.port = port
        self.backbone = backbone
        self.tls = tls
        self.reusePort = reusePort
        self.backlog = backlog
    }
}
