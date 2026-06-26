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
public import WebSocket

/// An HTTP/1.1 · HTTP/2 server that drives an ``HTTPResponder`` over a ``ServerTransport``.
///
/// The server is generic over the `Clock` its Slowloris/idle deadlines are timed against. Production
/// uses the real ``ContinuousClock`` (via the convenience initializer); a test injects a
/// deterministic clock, so the timeout paths run with zero real-time waiting.
public final class HTTPServer<C: Clock>: Sendable where C.Duration == Duration {
    let transport: any ServerTransport
    /// An optional QUIC transport run alongside the TCP one to serve HTTP/3 (RFC 9114).
    let quicTransport: (any QUICServerTransport)?
    /// The responder, hot-swappable at runtime via ``reloadResponder(_:)`` (G4a).
    ///
    /// Behind a `Mutex` — a `Sendable` existential — so a config reload can replace the routing table
    /// without a restart. Every dispatch reads it exactly once (`responder.withLock { $0 }`) and never
    /// holds the lock across the `await`, so an in-flight request finishes on the table it read while
    /// new requests pick up the new one: the graceful old/new split falls out with no drain.
    let responder: Mutex<any HTTPResponder>
    /// Handles connections that upgrade to WebSocket (RFC 6455 §4), or nil to refuse upgrades.
    let webSocketHandler: (any WebSocketHandler)?
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

    /// Live connection counts: a global total (``HTTPLimits/maxConnections``) and a per-host map
    /// (``HTTPLimits/maxConnectionsPerClient``), guarded together.
    ///
    /// A `Mutex` (not an actor) because the critical section is a single map/counter update with no
    /// `await`.
    private let connectionCounts = Mutex<ConnectionCounts>(ConnectionCounts())

    /// In-flight connections being served, keyed by id, registered/unregistered around ``serve(_:)``.
    ///
    /// ``shutdown(within:)`` force-closes any that have not drained by the deadline.
    let activeConnections = Mutex<[TransportConnectionID: any TransportConnection]>([:])

    /// Live connection accounting: a global total plus per-host counts.
    private struct ConnectionCounts {
        var total = 0
        var perHost: [String: Int] = [:]
    }

    /// Creates a server bound to `transport`, handling requests with `responder` and timing its
    /// Slowloris/idle deadlines against `clock`.
    public init(
        transport: any ServerTransport,
        responder: any HTTPResponder,
        quicTransport: (any QUICServerTransport)? = nil,
        webSocketHandler: (any WebSocketHandler)? = nil,
        limits: HTTPLimits = .default,
        clock: C
    ) {
        self.transport = transport
        self.quicTransport = quicTransport
        self.responder = Mutex(responder)
        self.webSocketHandler = webSocketHandler
        self.limits = limits
        self.clock = clock
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Starts accepting connections and serves each concurrently until the transport finishes.
    ///
    /// When a ``QUICServerTransport`` was supplied it is run alongside the TCP listener to serve
    /// HTTP/3 (RFC 9114), and `Alt-Svc` (RFC 7838) is advertised on the h1/h2 responses.
    public func run() async throws {
        let connections = try await transport.start()
        await withDiscardingTaskGroup { group in
            if quicTransport != nil {
                group.addTask { await self.runHTTP3() }
            }
            for await connection in connections {
                group.addTask { await self.accept(connection) }
            }
        }
    }

    /// Atomically swaps the responder so subsequent requests are served by `responder` (G4a — a hot
    /// route / handler reload with no restart).
    ///
    /// A request reads the responder once at dispatch, so this needs no drain: requests already
    /// in flight finish on the table they read, and every request dispatched after this call uses the
    /// new one. Safe to call from any task while the server is running.
    public func reloadResponder(_ responder: any HTTPResponder) {
        self.responder.withLock { $0 = responder }
    }

    /// The current responder, read once under the lock (never held across a dispatch's `await`) — the
    /// single hot-swap read point (G4a).
    ///
    /// A dispatch reads this exactly once, then awaits the returned responder, so an in-flight request
    /// finishes on the table it read while a concurrent ``reloadResponder(_:)`` only affects requests
    /// dispatched afterward. Centralized here so the protocol-engine dispatch files need not import the
    /// synchronization primitive.
    var currentResponder: any HTTPResponder { responder.withLock(\.self) }

    /// Admits `connection` if it is under both the global (``HTTPLimits/maxConnections``) and
    /// per-client (``HTTPLimits/maxConnectionsPerClient``) caps, serves it for its lifetime, then
    /// releases the slot.
    ///
    /// A connection over either cap is closed immediately — a resource-exhaustion defense (the spirit
    /// of a 429): the per-client cap (T-F4) blunts a single source, the global cap (audit T-F2) bounds
    /// total live connections so a many-source flood cannot exhaust file descriptors / tasks.
    private func accept(_ connection: any TransportConnection) async {
        let host = connection.peer.host
        let admitted = connectionCounts.withLock { counts in
            guard counts.total < limits.maxConnections else {
                return false
            }
            let current = counts.perHost[host, default: 0]
            guard current < limits.maxConnectionsPerClient else {
                return false
            }
            counts.perHost[host] = current + 1
            counts.total += 1
            return true
        }
        guard admitted else {
            await connection.close()
            return
        }
        await serve(connection)
        connectionCounts.withLock { counts in
            counts.total -= 1
            guard let current = counts.perHost[host] else {
                return
            }
            if current <= 1 {
                counts.perHost[host] = nil
            }
            else {
                counts.perHost[host] = current - 1
            }
        }
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
                while await self.serveOne(connection, deadline: deadline, buffer: &buffer) {
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
        webSocketHandler: (any WebSocketHandler)? = nil,
        limits: HTTPLimits = .default
    ) {
        self.init(
            transport: transport,
            responder: responder,
            quicTransport: quicTransport,
            webSocketHandler: webSocketHandler,
            limits: limits,
            clock: ContinuousClock()
        )
    }
}
