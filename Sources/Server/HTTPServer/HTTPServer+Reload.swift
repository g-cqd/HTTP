//
//  HTTPServer+Reload.swift
//  HTTPServer
//
//  G4b — hot TLS certificate reload. Delegates to the transport's restart-based reload: the listener
//  is rebound with the new identity on the same port while already-accepted connections keep serving
//  on the old one (zero existing-connection drops). Cleartext and non-Network.framework backbones throw
//  `TransportError.unsupported` via the `ServerTransport` protocol default. Pairs with the in-process
//  responder hot-swap (`reloadResponder`, G4a) for a fully restart-free config reload.
//

public import HTTPTransport

extension HTTPServer {
    /// Hot-reloads the server's TLS identity to `tls` (G4b) without dropping existing connections.
    ///
    /// New handshakes use `tls`; connections already accepted keep serving on the identity they
    /// handshook with — the transport rebinds its listener on the same port, and accepted
    /// `NWConnection`s are independent of the listener. Throws ``TransportError/unsupported(_:)`` on a
    /// cleartext or non-Network.framework backbone, or a bind / identity error if the new `tls` cannot
    /// be loaded (in which case the running listener is left untouched).
    public func reloadCertificate(_ tls: TransportTLS) async throws {
        try await transport.reload(tls: tls)
    }
}
