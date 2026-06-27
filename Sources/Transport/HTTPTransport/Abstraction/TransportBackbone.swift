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

    /// apple/swift-system typed descriptor wrappers over the POSIX socket syscalls.
    case swiftSystem

    /// In-memory transport for deterministic tests (no sockets).
    case fake
}
