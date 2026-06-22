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

    /// Creates a transport configuration.
    public init(host: String = "127.0.0.1", port: UInt16, backbone: TransportBackbone) {
        self.host = host
        self.port = port
        self.backbone = backbone
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

    /// The connection or listener has already been closed.
    case closed
}
