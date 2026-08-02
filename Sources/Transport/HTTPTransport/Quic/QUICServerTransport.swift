//
//  QUICServerTransport.swift
//  HTTPTransport
//
//  The server-side QUIC transport abstraction for HTTP/3 — a parallel triad to the single-stream
//  ``ServerTransport`` (it yields multiplexed ``QUICConnection``s, not byte streams). Two backbones
//  implement it, selected by OS version through ``QUICTransportFactory``: the legacy
//  `NWConnectionGroup` path at the macOS 15 floor, and the modern `NetworkConnection<QUIC>` path on
//  macOS 26+.
//

/// A server-side QUIC transport: binds a UDP port and yields inbound QUIC connections (RFC 9000).
public protocol QUICServerTransport: Sendable {
    /// The actual bound UDP port (meaningful after ``start()``; resolves an ephemeral `0` request).
    var boundPort: UInt16 { get }

    /// The local endpoint actually bound after ``start()`` — the resolved interface literal, its
    /// family, and the realized UDP port — or `nil` before binding.
    ///
    /// The same first-class contract as ``ServerTransport/boundEndpoint``, and the property audit
    /// F-04 was about: this backbone advertised a port through `Alt-Svc` (RFC 7838) while binding a
    /// different one, so "what did you actually bind" had no answer a caller could act on. Both QUIC
    /// backbones implement it.
    var boundEndpoint: BindEndpoint? { get }

    /// Binds and begins accepting, returning a stream of inbound connections that finishes at shutdown.
    ///
    /// `admission` is the shared connection ceiling (audit F8), charged before a connection is yielded
    /// so a QUIC peer counts against the same budget as a TCP one. A QUIC listener has no readiness
    /// source to suspend, so refusing the connection (CONNECTION_CLOSE, RFC 9000 §19.19) *is* the
    /// backpressure. Pass `nil` (see ``start()``) for an ungated listener.
    func start(admission: ConnectionAdmission?) async throws -> AsyncStream<any QUICConnection>

    /// Stops accepting and closes the listener.
    func shutdown() async
}

extension QUICServerTransport {
    /// Binds and begins accepting with **no** admission ceiling applied at the transport.
    ///
    /// The ungated entry point, for the tests and tools that drive a QUIC listener directly.
    public func start() async throws -> AsyncStream<any QUICConnection> {
        try await start(admission: nil)
    }
}
