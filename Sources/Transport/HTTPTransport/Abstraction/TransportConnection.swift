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

    /// Receives up to `maxLength` inbound bytes, **appending** them to `buffer`, and returns the number
    /// of bytes appended (`0` at EOF).
    ///
    /// This is the allocation-lean read path: a backbone that owns a reusable read buffer overrides it to
    /// read straight into that scratch and copy only the received bytes into `buffer` — no fresh per-read
    /// chunk. The default below adapts ``receive(maxLength:)`` for backbones that cannot (Network.framework
    /// hands back its own `Data`).
    func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int

    /// Sends `bytes` to the peer, completing once they are handed to the OS.
    func send(_ bytes: [UInt8]) async throws

    /// Closes the connection gracefully, flushing any pending output.
    func close() async

    /// The task executor this connection's serve task should prefer, or `nil` to use the global
    /// cooperative pool.
    ///
    /// An event-loop backbone returns **its own loop** (a `TaskExecutor`): pinning the serve task to it
    /// runs read → parse → route → respond → write **inline on the loop thread**, with no hop to the
    /// cooperative pool — the median-latency parity path with the blocking backbone, which the kernel
    /// wakes directly on its read thread (audit R4). `nil` (the default) keeps the prior behavior.
    var preferredTaskExecutor: (any TaskExecutor)? { get }
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

    /// No executor preference by default — the serve task runs on the global cooperative pool.
    ///
    /// The kqueue/epoll backbones override this to return their loop so the serve task runs inline on it.
    public var preferredTaskExecutor: (any TaskExecutor)? { nil }

    /// Default ``receive(into:maxLength:)``: read one chunk via ``receive(maxLength:)`` and append it.
    ///
    /// Used by backbones that cannot read into a caller buffer (Network.framework returns its own `Data`)
    /// and the in-memory test fakes — behaviour-identical to the prior `receive` + `append`. The POSIX
    /// backbones override it to drop the per-read allocation.
    public func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
        guard let chunk = try await receive(maxLength: maxLength), !chunk.isEmpty else {
            return 0
        }
        buffer.append(contentsOf: chunk)
        return chunk.count
    }
}
