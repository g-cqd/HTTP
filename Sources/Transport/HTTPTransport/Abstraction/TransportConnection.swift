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
    /// Populated only by a TLS backbone configured for ``TransportTLS/ClientAuth/required`` (or
    /// ``TransportTLS/ClientAuth/optional`` with a certificate presented), captured once the
    /// handshake settles. The server asserts it into the request context (zero-trust /
    /// service-to-service identity). The shorthand for ``tlsPeerIdentity``'s subject.
    var tlsPeerSubject: String? { get }

    /// The peer's full verified client-certificate identity (mutual TLS) — the DER chain, leaf
    /// subject, and leaf Subject Alternative Names — or `nil` when no client certificate was
    /// presented (G3: the richer form of ``tlsPeerSubject``).
    var tlsPeerIdentity: TLSPeerIdentity? { get }

    /// Receives up to `maxLength` inbound bytes, or `nil` once the peer half-closes (EOF).
    ///
    /// Honors task cancellation **per call**: cancelling the task awaiting a receive — any task, not
    /// only the serve task carrying the connection-wide handler (audit CC4), e.g. an idle-watchdog's
    /// child task — tears the connection down (``cancel()``) and the parked call resumes promptly,
    /// throwing `CancellationError`. Teardown rather than a bare unblock, because a byte stream cannot
    /// abandon an in-flight read without losing its framing.
    func receive(maxLength: Int) async throws -> [UInt8]?

    /// Receives up to `maxLength` inbound bytes, **appending** them to `buffer`, and returns the number
    /// of bytes appended (`0` at EOF).
    ///
    /// This is the allocation-lean read path: a backbone that owns a reusable read buffer reads straight
    /// into that scratch and copies only the received bytes into `buffer` — no fresh per-read chunk —
    /// and holds its inbound lease across BOTH steps, so the copy-out cannot be taken from under the
    /// operation that produced it. Cancellation follows the ``receive(maxLength:)`` contract: a cancelled
    /// call tears the connection down and throws `CancellationError` promptly.
    ///
    /// There is deliberately NO default here. The obvious one — receive a chunk, then append it — is
    /// two gated calls composing one logical operation, so a leased backbone that inherited it would run
    /// with a narrower ownership span than its own contract claims and no assertion of its own able to
    /// see that. A conformer with nothing to lease gets that adapter by conforming to
    /// ``UnleasedTransportConnection`` and saying so; everyone else answers this requirement.
    func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int

    /// Sends `bytes` to the peer, completing once they are handed to the OS.
    func send(_ bytes: [UInt8]) async throws

    /// Sends `head` immediately followed by `body` as one logical message (a response: header section
    /// then body), completing once both are handed to the OS.
    ///
    /// The default coalesces into a single buffer and calls ``send(_:)``; an event-driven POSIX backbone
    /// overrides it with a `writev` scatter-gather that puts both buffers on the wire in one syscall with
    /// no coalesce copy (audit #4 / L4).
    func send(_ head: [UInt8], _ body: [UInt8]) async throws

    /// Sends `length` octets of the open file `descriptor`, starting at byte `offset`, to the peer
    /// (G5 zero-copy static serving).
    ///
    /// A raw-socket backbone implements it with `sendfile(2)` — the kernel moves file pages straight
    /// to the socket, no userspace copy. A backbone that cannot reach a raw socket copies instead:
    /// Network.framework exposes no file-send on `NWConnection`, so it takes the `pread` + ``send(_:)``
    /// adapter on ``UnleasedTransportConnection``, byte-identical with two extra copies. A backbone
    /// that leases its outbound direction must NOT take that adapter — its `send(_:)` call sits inside
    /// the chunk loop, so the lease would be released mid-body; the portable TLS backbone passes every
    /// byte through `SSL_write` (kernel TLS is out of scope) under one lease of its own. The caller
    /// owns `descriptor` (the transport never closes it) and applies its own protocol framing —
    /// only an UNFRAMED body span (HTTP/1.1 with a known `Content-Length`) is eligible; h2/h3 wrap
    /// body bytes in frames, so a raw file-to-socket copy is inapplicable there by design.
    func sendFile(descriptor: Int32, offset: Int, length: Int) async throws

    /// Closes the connection gracefully, flushing any pending output.
    func close() async

    /// Closes the connection's descriptor **now**, synchronously, to unblock any pending I/O.
    ///
    /// The synchronous counterpart of ``close()``: the server registers one ``cancel()`` per connection
    /// as the cancellation handler covering its whole serve loop, so cancelling that task closes the fd
    /// once and resumes any read/write parked in a continuation. Socket backbones additionally install
    /// a per-call handler around a **parked** receive (never on the data-ready hot path — audit CC4),
    /// so a child-task cancel honors the ``receive(maxLength:)`` contract; both handlers funnel into
    /// this idempotent close. A socket backbone overrides it to close its descriptor synchronously;
    /// the in-memory fakes keep the no-op default below.
    func cancel()

    /// The admission slot charged for this connection at accept time (audit F8), released when the
    /// server's serve loop ends.
    ///
    /// A gated backbone charges the slot before it yields the connection — before any serve task
    /// exists — and hands the ticket here, so the ceiling covers connections that are merely queued or
    /// still handshaking, not only ones being served. `nil` for a connection accepted without a gate
    /// (the in-memory fakes, benchmarks); the server then charges its own slot on dequeue.
    var admissionTicket: AdmissionTicket? { get }

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

    /// No client certificate by default; a TLS backbone doing mutual TLS overrides this with the
    /// full verified identity once the handshake settles (G3).
    public var tlsPeerIdentity: TLSPeerIdentity? { nil }

    /// No admission slot by default — a connection from an ungated backbone (the in-memory fakes,
    /// benchmarks) carries none, and the server charges its own on dequeue (audit F8).
    public var admissionTicket: AdmissionTicket? { nil }

    /// No executor preference by default — the serve task runs on the global cooperative pool.
    ///
    /// The kqueue/epoll backbones override this to return their loop so the serve task runs inline on it.
    public var preferredTaskExecutor: (any TaskExecutor)? { nil }

    /// No-op by default — an in-memory fake (no socket) has nothing to unblock; a socket backbone
    /// overrides this to close its descriptor synchronously (audit CC4).
    public func cancel() {
        // No descriptor to close: a fake's I/O completes without parking on a syscall.
    }

    /// Default ``send(_:_:)``: coalesce `head` + `body` into one buffer and send it (the copy a `writev`
    /// override avoids).
    ///
    /// Backbones without a raw socket fd (Network.framework / QUIC) keep this.
    public func send(_ head: [UInt8], _ body: [UInt8]) async throws {
        if body.isEmpty {
            try await send(head)
        }
        else {
            var combined = head
            combined.append(contentsOf: body)
            try await send(combined)
        }
    }
}
