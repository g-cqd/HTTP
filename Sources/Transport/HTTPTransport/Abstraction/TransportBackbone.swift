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

    /// Portable libssl-over-POSIX-socket TLS (system OpenSSL today, vendored BoringSSL later) — the
    /// non-Network.framework TLS path (ADR 0004). Available only in the opt-in `HTTP_PORTABLE_TLS`
    /// build; selecting it otherwise is a build-configuration error (see ``TransportFactory``).
    case portableTLS

    /// BSD sockets with a hand-rolled kqueue readiness loop — closest to the hardware.
    case posixKqueue

    /// BSD sockets with a hand-rolled `epoll(7)` readiness loop — the Linux mirror of ``posixKqueue``.
    /// Available only on Linux (`canImport(Glibc)`); selecting it elsewhere is a configuration error
    /// (see ``TransportFactory``). **WIP — not yet verified on a Linux toolchain.**
    case posixEpoll

    /// BSD sockets with GCD `DispatchSource` readiness (kqueue under the hood, less hand-rolled).
    case posixDispatch

    /// apple/swift-system typed `FileDescriptor` wrappers over the POSIX socket syscalls — **event-driven**
    /// over the shared kqueue loop (audit R4), the swift-system-typed twin of ``posixKqueue``.
    ///
    /// Originally a blocking thread-per-connection reference (fast median, but a fat p99/p99.9 tail from
    /// thread oversubscription — ~68 threads for 64 connections on 8 cores), it was converted to
    /// non-blocking `FileDescriptor` I/O driven by the same N-sharded, executor-pinned event loop as
    /// ``posixKqueue``, so it now shares that backbone's median **and** tight tail; it differs only in
    /// doing its syscalls through swift-system's typed API.
    case swiftSystem

    /// A UNIX-domain stream socket listener (`AF_UNIX`, POSIX.1-2017) — cleartext, for reverse-proxy
    /// upstreams, sidecars, and same-host IPC.
    ///
    /// Rides the platform's event-driven readiness loop (the ``posixKqueue`` machinery on Darwin,
    /// ``posixEpoll`` on Linux) — only the listener's address family differs, so accepted connections
    /// get the same sharded, executor-pinned I/O (audit R4) and the same `sendfile(2)` path.
    /// Requires ``TransportConfiguration/unixSocketPath``; `host`/`port` are ignored and `boundPort`
    /// stays `0`. TLS is not offered on this backbone (a local socket's trust boundary is the
    /// filesystem permission on the path).
    case unixDomainSocket

    /// In-memory transport for deterministic tests (no sockets).
    case fake

    /// The recommended general-purpose backbone for the current platform: the event-driven,
    /// "closest to the hardware" readiness loop — ``posixKqueue`` on Darwin, ``posixEpoll`` on Linux —
    /// sharded one loop per core with each connection's serve task pinned to its loop (audit R4), so the
    /// median rivals an inline blocking read while a bounded thread count keeps the tail tight.
    ///
    /// (``swiftSystem`` is the same event-driven, sharded, pinned model over swift-system's typed
    /// `FileDescriptor`, so it performs equivalently.) TLS — and thus h2-over-TLS / h3 — is a separate
    /// axis: use ``networkFramework`` or ``portableTLS`` when a secure listener is needed.
    public static var recommended: Self {
        #if canImport(Glibc)
            .posixEpoll
        #else
            .posixKqueue
        #endif
    }
}
