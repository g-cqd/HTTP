//
//  TransportError.swift
//  HTTPTransport
//
//  The switchable backbone flag, its configuration, and transport errors.
//

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
