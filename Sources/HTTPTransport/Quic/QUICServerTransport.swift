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

    /// Binds and begins accepting, returning a stream of inbound connections that finishes at shutdown.
    func start() async throws -> AsyncStream<any QUICConnection>

    /// Stops accepting and closes the listener.
    func shutdown() async
}
