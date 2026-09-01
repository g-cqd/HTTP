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

    /// The local endpoint actually bound after ``start()`` — the resolved interface literal, its
    /// family, and the realized port — or `nil` before binding, or when a backbone cannot report it.
    ///
    /// First-class rather than a test affordance. Both halves of the configuration can differ from
    /// what was asked for: `port` `0` means "whichever the OS chose", and `host` may have been a name
    /// or a wildcard. An operator log, a health check, and the `Alt-Svc` advertisement (RFC 7838) all
    /// need the realized answer, and audit F-04 is exactly what happens when the realized answer is
    /// only knowable indirectly — a QUIC listener bound one port and advertised it while every client
    /// dialled the configured one.
    ///
    /// The default returns `nil`. Every socket-backed backbone the package ships overrides it — the
    /// Network.framework backbones, all four POSIX backbones (`POSIXKqueue`, `POSIXDispatch`,
    /// `SwiftSystem`, `POSIXEpoll`), and `PortableTLS` — reading the realized endpoint back with
    /// `getsockname(2)`; the bind-contract matrix asserts every one of them rather than skipping the
    /// cell. The default remains only for a backbone with no socket to ask (the in-memory fake).
    var boundEndpoint: BindEndpoint? { get }

    /// Binds and begins accepting, returning a stream of inbound connections that finishes when the
    /// transport is shut down.
    ///
    /// `admission` is the shared connection ceiling (audit F8). A backbone charges a slot the instant
    /// `accept(2)` hands it a descriptor and **before** it yields anything, attaching the resulting
    /// ``AdmissionTicket`` to the connection; a refused connection is closed there and never yielded,
    /// and a backbone that has saturated the gate stops re-arming its accept source until the gate's
    /// resume fires. Pass `nil` (see ``start()``) for an ungated listener — benchmarks and the
    /// in-memory fakes, where the server applies the ceiling itself.
    ///
    /// The bound on the returned stream's depth comes from `admission`, not from a buffering policy:
    /// see the accept-loop comments in each backbone for why the stream stays `.unbounded`.
    func start(admission: ConnectionAdmission?) async throws -> AsyncStream<any TransportConnection>

    /// Stops accepting and closes the listener.
    func shutdown() async

    /// Hot-reloads the server's TLS identity (G4b): subsequent handshakes use `tls` while already
    /// accepted connections keep serving on the identity they handshook with.
    ///
    /// Restart-based — the backbone rebinds its listener on the same port — because the only TLS
    /// backbone today (Network.framework) fixes the server identity at listen time. The default throws
    /// ``TransportError/unsupported(_:)``: a cleartext or non-Network.framework listener has no identity
    /// to swap. SNI multi-cert and `.optional` client-auth wait on the portable TLS backbone (G0).
    func reload(tls: TransportTLS) async throws
}

extension ServerTransport {
    /// A backbone that cannot yet report its realized local endpoint reports nothing, never a guess.
    ///
    /// Synthesizing one from ``boundPort`` alone would have to invent the interface, which is the
    /// error this property exists to prevent.
    public var boundEndpoint: BindEndpoint? {
        nil
    }

    /// Binds and begins accepting with **no** admission ceiling applied at the transport.
    ///
    /// The ungated entry point, for a caller that owns the ceiling itself (``HTTPServer`` charges
    /// every connection it dequeues) or has none (benchmarks, the conformance battery). Prefer
    /// ``start(admission:)`` in a server: only a transport-level gate can refuse a connection before
    /// it is queued (audit F8).
    public func start() async throws -> AsyncStream<any TransportConnection> {
        try await start(admission: nil)
    }

    /// Cleartext and the non-Network.framework backbones have no server TLS identity to swap, so a
    /// reload is unsupported; the Network.framework backbone overrides this.
    public func reload(tls _: TransportTLS) async throws {
        throw TransportError.unsupported("TLS reload is unsupported by the \(backbone) backbone")
    }
}
