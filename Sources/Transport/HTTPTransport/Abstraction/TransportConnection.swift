//
//  TransportConnection.swift
//  HTTPTransport
//
//  The backbone-agnostic connection abstraction. Backbones bridge their native I/O to these async
//  methods; the HTTP engines consume the protocol and never a concrete backbone.
//

/// A bidirectional byte stream to one connected peer.
///
/// Backbones bridge their native I/O — Network.framework callbacks, POSIX socket syscalls, kqueue
/// or Dispatch readiness — to these async methods. Conformers are `Sendable` and honor task
/// cancellation; bytes cross the boundary as owned buffers that the parser wraps in a `ByteReader`.
public protocol TransportConnection: Sendable {
    /// A stable identifier for this connection.
    var id: TransportConnectionID { get }

    /// The peer's address (for logging and per-client connection limits).
    var peer: TransportAddress { get }

    /// The application protocol negotiated by TLS ALPN (RFC 7301) — e.g. `"h2"` or `"http/1.1"` —
    /// or `nil` over cleartext or before the handshake completes.
    ///
    /// When this is `"h2"` the connection is committed to HTTP/2 (RFC 9113 §3.3) and the server
    /// drives the HTTP/2 engine without preface sniffing; cleartext connections (`nil`) are sniffed.
    var negotiatedApplicationProtocol: String? { get }

    /// Whether transport-level encryption (TLS / QUIC) is active on this connection.
    ///
    /// When `true` the peer reached us over TLS, so the server advertised its ALPN protocols
    /// (RFC 7301) and requires the handshake to have settled on one it serves; a connection that
    /// negotiated none is refused rather than silently treated as HTTP/1.1 (ALPACA hardening,
    /// RFC 7301 §3.2). When `false` (cleartext) the protocol is decided by prior knowledge / sniffing.
    var isSecure: Bool { get }

    /// The subject summary of the peer's verified client certificate (mutual TLS), or `nil` when no
    /// client certificate was presented — cleartext, one-way TLS, or before the handshake settles.
    ///
    /// Populated only by a TLS backbone configured for ``TransportTLS/ClientAuth/required``, captured
    /// once the handshake reaches `.ready`. The server asserts it onto the request as the
    /// server-controlled `X-Client-Cert-Subject` field for handlers and middleware (zero-trust /
    /// service-to-service identity).
    var tlsPeerSubject: String? { get }

    /// Receives up to `maxLength` inbound bytes, or `nil` once the peer half-closes (EOF).
    func receive(maxLength: Int) async throws -> [UInt8]?

    /// Sends `bytes` to the peer, completing once they are handed to the OS.
    func send(_ bytes: [UInt8]) async throws

    /// Closes the connection gracefully, flushing any pending output.
    func close() async
}

extension TransportConnection {
    /// Cleartext and pre-handshake connections negotiate no application protocol; TLS backbones
    /// override this once ALPN (RFC 7301) resolves.
    public var negotiatedApplicationProtocol: String? { nil }

    /// Cleartext by default; a TLS-capable backbone overrides this to `true`.
    public var isSecure: Bool { false }

    /// No client certificate by default; a TLS backbone doing mutual TLS overrides this once the
    /// handshake settles.
    public var tlsPeerSubject: String? { nil }
}
