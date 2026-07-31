//
//  HTTPServer.swift
//  HTTPServer
//
//  The HTTP/1.1 server runtime: accepts connections from any transport backbone, fans them out
//  across cores with a task group, and serves each by streaming bytes through the sans-I/O HTTP/1.1
//  parser, invoking the responder, and serializing the reply.
//

internal import HTTP1
internal import HTTP2
public import HTTPCore
public import HTTPTransport
internal import Synchronization

/// An HTTP/1.1 · HTTP/2 server that drives an ``HTTPResponder`` over a ``ServerTransport``.
///
/// The server is generic over the `Clock` its Slowloris/idle deadlines are timed against. Production
/// uses the real ``ContinuousClock`` (via the convenience initializer); a test injects a
/// deterministic clock, so the timeout paths run with zero real-time waiting.
public final class HTTPServer<C: Clock>: Sendable where C.Duration == Duration {
    let transport: any ServerTransport
    /// An optional QUIC transport run alongside the TCP one to serve HTTP/3 (RFC 9114).
    let quicTransport: (any QUICServerTransport)?
    /// The current ``ResponderSnapshot``, hot-swappable at runtime via ``reloadResponder(_:)`` (G4a).
    ///
    /// Behind a `Mutex` so a config reload can replace the routing table without a restart. A request
    /// reads it exactly once — when its head completes — and carries the resulting snapshot through
    /// route resolution, body framing and dispatch, never holding the lock across an `await`. So an
    /// in-flight request finishes on the generation it read while new requests pick up the new one:
    /// the graceful old/new split falls out with no drain, and no request can straddle two generations
    /// (audit CR-F12).
    let snapshot: Mutex<ResponderSnapshot>
    let limits: HTTPLimits
    let clock: C
    /// The `Alt-Svc` value advertising HTTP/3 (RFC 7838), set once the QUIC listener binds its port.
    let altSvc = Mutex<String?>(nil)

    /// Set once ``shutdown()`` begins a graceful drain.
    ///
    /// The per-connection serve loops read it to finish the current exchange and then close (HTTP/1
    /// with `Connection: close`, HTTP/2 with a GOAWAY, RFC 9113 §6.8) instead of awaiting another
    /// request. The drain helpers live in `HTTPServer+Shutdown.swift`.
    let isShuttingDown = Atomic<Bool>(false)

    /// The shared connection ceiling — a global total (``HTTPLimits/maxConnections``) and a per-host
    /// budget (``HTTPLimits/maxConnectionsPerClient``) — handed to the transport at ``run()``.
    ///
    /// It lives at the transport layer (audit F8) so a slot is charged the instant a descriptor is
    /// accepted, *before* the connection is queued and before any serve task exists. This server-side
    /// reference exists to build the gate from ``limits``, to hand it to the transport, and to charge
    /// connections from an ungated backbone (the in-memory fakes) on dequeue.
    let admission: ConnectionAdmission

    /// In-flight connections being served, keyed by id, registered/unregistered around ``serve(_:)``.
    ///
    /// ``shutdown(within:)`` force-closes any that have not drained by the deadline.
    let activeConnections = Mutex<[TransportConnectionID: any TransportConnection]>([:])

    /// In-flight QUIC connections being served, keyed by a monotonic handle id (audit addendum P0.5).
    ///
    /// A QUIC connection is not a ``TransportConnection`` — it multiplexes streams rather than being
    /// one — so it needs its own registry; without it the drain reached only the TCP half of the
    /// server. ``shutdown(within:)`` GOAWAYs each of these, then force-closes whatever has not drained.
    let activeQUICConnections = Mutex<[Int: HTTP3Handle]>([:])

    /// The source of ``activeQUICConnections`` keys — a QUIC connection has no transport-assigned id.
    let nextQUICHandleID = Atomic<Int>(0)

    /// Creates a server bound to `transport`, handling requests with `responder` and timing its
    /// Slowloris/idle deadlines against `clock`.
    public init(
        transport: any ServerTransport,
        responder: any HTTPResponder,
        quicTransport: (any QUICServerTransport)? = nil,
        limits: HTTPLimits = .default,
        clock: C
    ) {
        self.transport = transport
        self.quicTransport = quicTransport
        self.snapshot = Mutex(ResponderSnapshot(responder, generation: 0))
        self.limits = limits
        self.clock = clock
        self.admission = ConnectionAdmission(
            capacity: ConnectionAdmission.Capacity(
                total: limits.maxConnections,
                perHost: limits.maxConnectionsPerClient,
                resumeRatio: limits.acceptResumeRatio
            )
        )
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Starts accepting connections and serves each concurrently until the transport finishes.
    ///
    /// When a ``QUICServerTransport`` was supplied it is run alongside the TCP listener to serve
    /// HTTP/3 (RFC 9114), and `Alt-Svc` (RFC 7838) is advertised on the h1/h2 responses.
    public func run() async throws {
        let connections = try await transport.start(admission: admission)
        await withDiscardingTaskGroup { group in
            if quicTransport != nil {
                group.addTask(priority: .userInitiated) { await self.runHTTP3() }
            }
            for await connection in connections {
                // `.userInitiated` matches the transport queues' QoS (audit: tail-latency variance): the
                // request handler runs on the cooperative pool, and without this its threads sit a tier
                // below the I/O queues — every continuation resume becomes a QoS downgrade hop, and the
                // pool gets descheduled under contention, fattening p99/p99.9.
                group.addTask(priority: .userInitiated) { await self.accept(connection) }
            }
        }
    }

    /// Atomically swaps the responder so subsequent requests are served by `responder` (G4a — a hot
    /// route / handler reload with no restart).
    ///
    /// A request reads the responder once when its head completes, so this needs no drain: requests
    /// already in flight finish on the table they read, and every request whose head completes after
    /// this call uses the new one. Safe to call from any task while the server is running.
    public func reloadResponder(_ responder: any HTTPResponder) {
        snapshot.withLock { current in
            current = ResponderSnapshot(responder, generation: current.generation &+ 1)
        }
    }

    /// The current generation, read once under the lock (never held across an `await`) — the single
    /// hot-swap read point (G4a).
    ///
    /// A request reads this exactly once, when its head completes, and then carries the returned value
    /// through route resolution, body framing and dispatch. So an in-flight request finishes on the
    /// generation it read while a concurrent ``reloadResponder(_:)`` only affects requests whose heads
    /// complete afterward, and no request can mix two generations (audit CR-F12). Centralized here so
    /// the protocol-engine dispatch files need not import the synchronization primitive.
    var currentSnapshot: ResponderSnapshot { snapshot.withLock(\.self) }

    /// The ``RequestBody`` to hand a responder for `request`: an incremental ``RequestBody/stream(_:)``
    /// when the matched route opted in (Phase 1.4), else the buffered bytes.
    ///
    /// On HTTP/1.1 the reader streams the body off the wire directly; on HTTP/2 / HTTP/3 the sans-I/O
    /// engine has already received the whole body (bounded by the per-route limit), so a streaming route
    /// is served those bytes wrapped as a one-shot stream — the handler API is uniform across protocols,
    /// and truly incremental h2/h3 delivery is a follow-up (see `docs/adr/0006-…`).
    func requestBody(
        _ body: [UInt8],
        for request: HTTPRequest,
        in snapshot: ResponderSnapshot
    ) -> RequestBody {
        let resolved = snapshot.resolver?
            .match(method: request.method, path: request.path, isUpgrade: false)
        return resolved?.route.streamsBody == true
            ? .stream(HTTPRequestBodyStream(yielding: body))
            : .collected(body)
    }

    /// Takes ownership of the admission slot charged for `connection`, serves it for its lifetime,
    /// then releases the slot.
    ///
    /// A gated backbone already charged the slot at accept time — before this connection was queued
    /// and before this task existed (audit F8) — so the common path is pure adoption. A connection
    /// from an ungated backbone (the in-memory fakes) carries no ticket and is charged here instead,
    /// still before any serve work, so the ceiling holds on every backbone.
    ///
    /// A connection over either cap is closed immediately — a resource-exhaustion defense (the spirit
    /// of a 429, RFC 9110 §15.5.30): the per-client cap (T-F4) blunts a single source, the global cap
    /// (audit T-F2) bounds total live connections so a many-source flood cannot exhaust file
    /// descriptors / tasks.
    private func accept(_ connection: any TransportConnection) async {
        guard let ticket = connection.admissionTicket ?? charge(connection) else {
            await connection.close()
            return
        }
        // Held for the whole serve loop, then returned — which is also what frees the accept source to
        // re-arm once enough slots come back (the gate's hysteresis watermark).
        defer { ticket.release() }
        // Pin the serve task to the connection's preferred executor when it has one (the kqueue/epoll
        // loop): read → parse → route → respond → write then run inline on the loop thread with no hop
        // to the cooperative pool — median-latency parity with the blocking backbone (audit R4). `nil`
        // (every other backbone) means no preference: the global pool, exactly as before.
        await withTaskExecutorPreference(connection.preferredTaskExecutor) {
            await serve(connection)
        }
    }

    /// Charges an admission slot for a connection its backbone did not charge for, or `nil` when it is
    /// over the global or per-client ceiling.
    private func charge(_ connection: any TransportConnection) -> AdmissionTicket? {
        guard case .admitted(let ticket, _) = admission.admit(host: connection.peer.host) else {
            return nil
        }
        return ticket
    }

    /// Serves a connection for its lifetime, dispatching by protocol, then closes.
    ///
    /// The first octets are sniffed: a connection that opens with the HTTP/2 client preface (h2c
    /// "prior knowledge", RFC 9113 §3.4) is driven by the HTTP/2 engine; anything else is HTTP/1.x.
    /// The distinctive prefix "PRI * HTTP/2.0\r\n" that no HTTP/1 request line can match; once it is
    /// seen the connection is committed to HTTP/2 even if the *full* preface then proves invalid (so
    /// the engine can answer with GOAWAY rather than mis-routing to HTTP/1).
    func serve(_ connection: any TransportConnection) async {
        activeConnections.withLock { $0[connection.id] = connection }
        defer { activeConnections.withLock { $0[connection.id] = nil } }
        // One cancellation handler covers the connection's whole serve loop (audit CC4): cancelling the
        // serve task closes the fd once via `cancel()`, which unblocks whatever read/write is parked in a
        // continuation right now — instead of registering a task-status record on every receive/send the
        // keep-alive loop awaits. The I/O bodies run directly, with no per-op handler.
        await withTaskCancellationHandler {
            await serveBody(connection)
        } onCancel: {
            connection.cancel()
        }
    }

    /// The protocol-dispatch + keep-alive serve work, run inside the connection-wide cancellation handler
    /// installed by ``serve(_:)`` (audit CC4).
    ///
    /// Closes the connection on every exit path.
    private func serveBody(_ connection: any TransportConnection) async {
        // TLS ALPN (RFC 7301) settles the protocol before any byte is read: "h2" commits the
        // connection to HTTP/2 (RFC 9113 §3.3), so the engine — not the preface sniffer — drives it
        // (a malformed preface then earns a GOAWAY instead of mis-routing to HTTP/1.1). Any other
        // negotiated value, or cleartext (nil), falls through to the h2c/HTTP-1 sniff below.
        if connection.negotiatedApplicationProtocol == "h2" {
            await withIdleWatchdog(connection) { deadline in
                await self.serveHTTP2(connection, deadline: deadline, initialBytes: [])
            }
            await connection.close()
            return
        }

        // ALPACA hardening (RFC 7301 §3.2): over TLS we advertised our ALPN protocols, so the
        // handshake must have settled on one we serve. "h2" is handled above; "http/1.1" is the only
        // other value we serve. Anything else — including no ALPN at all — is refused (closed) rather
        // than silently downgraded to HTTP/1.1. Cleartext (`isSecure == false`) is unaffected: it is
        // routed by h2c-preface sniffing / prior knowledge below.
        if connection.isSecure, connection.negotiatedApplicationProtocol != "http/1.1" {
            await connection.close()
            return
        }

        await withIdleWatchdog(connection) { deadline in
            var buffer: [UInt8] = []
            // Read until the 16-octet marker is confirmed or the start diverges from it (HTTP/1.x).
            while buffer.count < Self.http2MarkerLength, Self.couldBeHTTP2Preface(buffer) {
                deadline.arm(self.clock.now.advanced(by: self.limits.keepAliveTimeout))
                let chunk = try? await connection.receive(maxLength: 16_384)
                deadline.disarm()
                guard let chunk, !chunk.isEmpty else { break }
                buffer.append(contentsOf: chunk)
            }

            if Self.matchesHTTP2Marker(buffer) {
                await self.serveHTTP2(connection, deadline: deadline, initialBytes: buffer)
            }
            else {
                // A per-connection response buffer, reused across keep-alive exchanges so the
                // serializer allocates no fresh response storage after the first (audit: tail-latency
                // variance — fewer per-request mallocs, less allocator-lock contention).
                var responseBuffer: [UInt8] = []
                // A cursor marking where the next request begins in `buffer`; advancing it past a
                // consumed request is O(1), so a pipelined remainder is never memmoved to the front per
                // request (audit L3 — the keep-alive ring buffer). serveOne compacts the prefix lazily.
                var bufferStart = 0
                while await self.serveOne(
                    connection,
                    deadline: deadline,
                    buffer: &buffer,
                    start: &bufferStart,
                    responseBuffer: &responseBuffer
                ) {
                    // Loop until serveOne returns false (close); the work is the call itself.
                }
            }
        }
        await connection.close()
    }
}

extension HTTPServer where C == ContinuousClock {
    /// Creates a server timing its deadlines against the real ``ContinuousClock`` — the production
    /// default.
    ///
    /// Inject a deterministic clock with the designated initializer in tests.
    public convenience init(
        transport: any ServerTransport,
        responder: any HTTPResponder,
        quicTransport: (any QUICServerTransport)? = nil,
        limits: HTTPLimits = .default
    ) {
        self.init(
            transport: transport,
            responder: responder,
            quicTransport: quicTransport,
            limits: limits,
            clock: ContinuousClock()
        )
    }
}
