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

    /// The `listen(2)` backlog — the depth of the accepted-but-not-yet-`accept()`ed connection queue.
    ///
    /// macOS caps the effective value at `kern.ipc.somaxconn` (128 by default), so raising it past 128
    /// takes effect only on a tuned host (or matters per-worker under SO_REUSEPORT); the default is a
    /// sane ceiling either way, replacing the former hard-coded 128 (audit T-F14).
    public var backlog: Int32

    /// How many event loops the kqueue/epoll backbones shard across — one dedicated thread each, sharing
    /// the port via `SO_REUSEPORT`, serving its connections inline (audit R4 — p50 parity under load).
    ///
    /// `nil` auto-sizes to the active processor count. `1` reproduces the single-loop behavior. Ignored
    /// by the non-event-loop backbones (swiftSystem, Dispatch, Network.framework).
    public var eventLoopCount: Int?

    /// The filesystem path a ``TransportBackbone/unixDomainSocket`` listener binds (`AF_UNIX`,
    /// POSIX.1-2017), or `nil` for the TCP backbones.
    ///
    /// A stale socket file at the path is unlinked before bind (the standard daemon restart
    /// behavior); the file is left in place on shutdown. `host`/`port` are ignored for a UNIX-domain
    /// listener and ``ServerTransport/boundPort`` stays `0`.
    public var unixSocketPath: String?

    /// Creates a transport configuration.
    public init(
        host: String = "127.0.0.1",
        port: UInt16,
        backbone: TransportBackbone,
        tls: TransportTLS? = nil,
        reusePort: Bool = false,
        backlog: Int32 = 1_024,
        eventLoopCount: Int? = nil,
        unixSocketPath: String? = nil
    ) {
        self.host = host
        self.port = port
        self.backbone = backbone
        self.tls = tls
        self.reusePort = reusePort
        self.backlog = backlog
        self.eventLoopCount = eventLoopCount
        self.unixSocketPath = unixSocketPath
    }
}
