//
//  ServerTransport.swift
//  HTTPTransport
//
//  The server-side transport abstraction: one protocol, several switchable backbones.
//

/// A server-side transport: binds a port and yields inbound connections.
///
/// One abstraction with several switchable ``TransportBackbone`` implementations. The HTTP server
/// consumes this protocol — never a concrete backbone — so the sans-I/O engines stay I/O-agnostic.
/// Implementations bridge their native accept loop to an `AsyncStream`, which lets the server fan
/// connections out across cores with a task group.
public protocol ServerTransport: Sendable {
    /// Which backbone this instance is (for diagnostics and selection round-tripping).
    var backbone: TransportBackbone { get }

    /// The bound listener port after ``start()`` — the realized ephemeral port when bound with `0`;
    /// `0` before binding, or for a portless backbone (the in-memory fake).
    ///
    /// Exposed on the abstraction (not just the concrete backbones) so the server can advertise it
    /// (e.g. `Alt-Svc`) and so one conformance suite can drive every backbone uniformly.
    var boundPort: UInt16 { get }

    /// Binds and begins accepting, returning a stream of inbound connections that finishes when the
    /// transport is shut down.
    func start() async throws -> AsyncStream<any TransportConnection>

    /// Stops accepting and closes the listener.
    func shutdown() async
}
