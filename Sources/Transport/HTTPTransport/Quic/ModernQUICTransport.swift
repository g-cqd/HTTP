//
//  ModernQUICTransport.swift
//  HTTPTransport
//
//  Modern QUIC backbone (macOS 26+): the typed-channel Network API — `NetworkListener<QUIC>` +
//  `run` + `NetworkConnection<QUIC>.inboundStreams`. QUIC is configured with the builder `QUIC(alpn:)`
//  + `.tls.localIdentity(_:)` (the dev/identity TLS, RFC 9001) and the per-peer stream limits. The
//  handler-based `run` (which blocks for the listener's lifetime) is bridged to the
//  ``QUICServerTransport`` `AsyncStream`; each connection handler parks on the connection's inbound
//  loop so Network keeps it alive while the server drives it.
//
//  Standards: QUIC (RFC 9000) over UDP (RFC 768); QUIC-TLS (RFC 9001) with TLS 1.3 (RFC 8446); ALPN
//  (RFC 7301) selects "h3" for HTTP/3 (RFC 9114 §3.1). Gated to macOS 26+ via ``QUICTransportFactory``.
//

public import HTTPCore
internal import Network
internal import Synchronization

/// The modern Network.framework QUIC server backbone (`NetworkListener<QUIC>`, macOS 26+).
@available(macOS 26, iOS 26, *)
public final class ModernQUICTransport: QUICServerTransport {
    private let configuration: TransportConfiguration
    private let limits: HTTPLimits
    private let listenerBox = Mutex<Network.NetworkListener<Network.QUIC>?>(nil)
    private let runTask = Mutex<Task<Void, Never>?>(nil)

    /// Creates a modern QUIC transport for `configuration` (which must carry TLS) and `limits`.
    public init(configuration: TransportConfiguration, limits: HTTPLimits = .default) {
        self.configuration = configuration
        self.limits = limits
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// The actual bound UDP port (valid once the listener binds during ``start()``).
    public var boundPort: UInt16 {
        listenerBox.withLock { $0?.port?.rawValue ?? 0 }
    }

    /// Binds the QUIC listener and begins accepting, returning a stream of inbound connections.
    ///
    /// A QUIC listener has no readiness source to suspend, so the per-connection refusal *is* the
    /// backpressure (audit F8): a peer over the ceiling has its handler return immediately, which tears
    /// the connection down before a single HTTP/3 stream is read. The slot is charged before the
    /// connection is yielded and released when the handler returns — i.e. when the connection closes —
    /// so the QUIC peer counts against exactly the same budget as a TCP one.
    public func start(
        admission: ConnectionAdmission?
    ) async throws -> AsyncStream<any QUICConnection> {
        guard let tls = configuration.tls else {
            throw TransportError.tlsConfigurationFailed("QUIC requires a TLS identity")
        }
        let identity = try NetworkFrameworkTLS.identity(
            pkcs12: tls.pkcs12,
            passphrase: tls.passphrase
        )
        let alpn = tls.applicationProtocols
        let maxBidirectional = limits.maxConcurrentStreams
        let listener = try Network.NetworkListener {
            // 0-RTT early data is replayable (RFC 9001 §9.2). Network.framework's QUIC TLS (`QUIC.TLS`)
            // exposes no early-data control to the application — unlike TCP's `Network.TLS`, which has
            // `earlyDataEnabled(_:)` — and our configuration never enables 0-RTT, so no request is
            // processed from early data (the safe posture, with nothing to toggle here). Were a future
            // API to enable QUIC 0-RTT, the required defense is to reject a non-idempotent method
            // arriving in early data with 425 Too Early (RFC 8470); see the deferred-risky sub-plan.
            Network.QUIC(alpn: alpn)
                .tls.localIdentity(identity)
                .initialMaxBidirectionalStreams(maxBidirectional)
                .initialMaxUnidirectionalStreams(16)
        }
        listenerBox.withLock { $0 = listener }

        let (stream, continuation) = AsyncStream<any QUICConnection>.makeStream()
        let host = configuration.host
        let advertised = alpn.first
        let port = boundPort
        let task = Task {
            try? await listener.run { networkConnection in
                let peer = TransportAddress(host: host, port: port)
                // Charge before yielding. The handler blocks for the connection's whole lifetime, so
                // the ticket is scoped exactly to it — no bookkeeping on the connection object.
                let ticket: AdmissionTicket?
                switch admission?.admit(host: peer.host) {
                    case .rejectedTotal, .rejectedHost:
                        return  // returning tears the connection down: the refusal
                    case .admitted(let charged, _):
                        ticket = charged
                    case nil:
                        ticket = nil
                }
                defer { ticket?.release() }
                let connection = ModernQUICConnection(
                    connection: networkConnection,
                    peer: peer,
                    negotiatedApplicationProtocol: advertised,
                    admissionTicket: ticket
                )
                continuation.yield(connection)
                await connection.serve()  // blocks until the connection closes
            }
            continuation.finish()
        }
        runTask.withLock { $0 = task }
        await waitUntilBound()
        return stream
    }

    /// Stops accepting: cancels the listener's run task, which unwinds it (the modern API has no
    /// `cancel()`; teardown is via structured task cancellation).
    public func shutdown() async {
        runTask.withLock(\.self)?.cancel()
    }

    /// Polls until the listener has bound its port (so ``boundPort`` is valid before returning).
    private func waitUntilBound() async {
        for _ in 0 ..< 1_000 where boundPort == 0 {
            try? await Task.sleep(for: .milliseconds(5))
        }
    }
}
