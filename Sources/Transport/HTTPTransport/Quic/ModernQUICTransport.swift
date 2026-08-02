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
//  The listener is bound to the endpoint ``BindEndpoint`` resolves from the shared
//  ``TransportConfiguration`` — the same host/port contract every other backbone honours. Before audit
//  F-04 this backbone applied neither: it built its `NetworkListener` from the protocol stack alone, so
//  every h3 listener landed on an ephemeral UDP port regardless of what was configured, and the only
//  place the real port appeared was the `Alt-Svc` advertisement (RFC 7838). Any client that dials the
//  configured port — h3spec, `curl --http3-only`, a fixed firewall rule — reached nothing at all.
//
//  Standards: QUIC (RFC 9000) over UDP (RFC 768); QUIC-TLS (RFC 9001) with TLS 1.3 (RFC 8446); ALPN
//  (RFC 7301) selects "h3" for HTTP/3 (RFC 9114 §3.1). Gated to macOS 26+ via ``QUICTransportFactory``.
//

public import HTTPCore
internal import Network
internal import Synchronization

/// The modern Network.framework QUIC server backbone (`NetworkListener<QUIC>`, macOS 26+).
///
/// **Peer attribution.** Each accepted connection is charged to, and reports, the address its peer is
/// speaking from — taken from the connection's `currentPath` (see ``peer(of:)``), so an h3 client
/// counts against the same per-host ceiling as an h1/h2 client from the same address. Should Network
/// ever report no remote endpoint, the connection still serves but is attributed to
/// ``QUICPeer/unattributed`` rather than to a guess; every such connection then shares one admission
/// bucket and one rate-limit budget (fail-closed, CWE-770).
@available(macOS 26, iOS 26, *)
public final class ModernQUICTransport: QUICServerTransport {
    private let configuration: TransportConfiguration
    private let limits: HTTPLimits
    private let listenerBox = Mutex<Network.NetworkListener<Network.QUIC>?>(nil)
    private let runTask = Mutex<Task<Void, Never>?>(nil)
    private let bindState = Mutex<BindState>(BindState())

    /// Tracks the listener's progress toward a bound port so ``start(admission:)`` fails closed.
    private struct BindState {
        /// The endpoint requested, kept for diagnostics and for ``boundEndpoint``.
        var requested: BindEndpoint?
        /// The port the listener actually claimed, captured at its `.ready` transition.
        var boundPort: UInt16 = 0
        /// A terminal bind failure — the listener can never claim the configured endpoint.
        var failure: TransportError?
        /// The waiter parked in ``waitUntilBound()``, if it arrived before the outcome did.
        ///
        /// Checked rather than unsafe: this suspends once per ``start(admission:)``, so the checked
        /// continuation's bookkeeping is off every hot path and buys a real double-resume diagnostic.
        var waiter: CheckedContinuation<Void, any Error>?
    }

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
        bindState.withLock(\.boundPort)
    }

    /// The local endpoint actually bound — the resolved interface literal plus the realized UDP port.
    ///
    /// `nil` until ``start(admission:)`` binds. This is what `Alt-Svc` (RFC 7838) should advertise and
    /// what an operator needs in a log line: with a configured `port` of `0` the real port is only
    /// knowable after the bind, and with a configured host of `localhost` or a wildcard the real
    /// interface literal is only knowable after resolution.
    public var boundEndpoint: BindEndpoint? {
        bindState.withLock { current in
            guard let requested = current.requested, current.boundPort != 0 else {
                return nil
            }
            return BindEndpoint(
                address: requested.address,
                family: requested.family,
                port: current.boundPort
            )
        }
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
        let endpoint = try BindEndpoint.resolve(configuration)
        let localEndpoint = try endpoint.networkEndpoint()
        // The typed builder is where the modern API carries the local endpoint: `NetworkListener` has
        // no `on:` port parameter at all (unlike the legacy `NWListener(using:on:)`), which is exactly
        // how the port went missing. `localEndpoint(_:)` sets `NWParameters.requiredLocalEndpoint`, so
        // this and the legacy/TCP paths pin the bind through the same underlying mechanism. Nothing
        // here raises the package floor: this file is already `@available(macOS 26, iOS 26, *)` and the
        // legacy backbone below the floor keeps its own path.
        let builder = Network.NWParametersBuilder<Network.QUIC>
            .parameters {
                // 0-RTT early data is replayable (RFC 9001 §9.2). Network.framework's QUIC TLS
                // (`QUIC.TLS`) exposes no early-data control to the application — unlike TCP's
                // `Network.TLS`, which has `earlyDataEnabled(_:)` — and our configuration never enables
                // 0-RTT, so no request is processed from early data (the safe posture, with nothing to
                // toggle here). Were a future API to enable QUIC 0-RTT, the required defense is to
                // reject a non-idempotent method arriving in early data with 425 Too Early (RFC 8470);
                // see the deferred-risky sub-plan.
                Network.QUIC(alpn: alpn)
                    .tls.localIdentity(identity)
                    .initialMaxBidirectionalStreams(maxBidirectional)
                    .initialMaxUnidirectionalStreams(16)
            }
            .localEndpoint(localEndpoint)
            // Port sharing stays opt-in, matching every other backbone: without it a second, accidental
            // instance would silently share the UDP port instead of failing with EADDRINUSE.
            .localEndpointReuseAllowed(configuration.reusePort)
        let listener = try Self.makeListener(using: builder)
        listenerBox.withLock { $0 = listener }
        bindState.withLock { $0.requested = endpoint }
        let context = endpoint.description
        listener.onStateUpdate { [weak self] listener, state in
            self?.handle(state, of: listener, binding: context)
        }

        let (stream, continuation) = AsyncStream<any QUICConnection>.makeStream()
        let advertised = alpn.first
        let task = Task { [weak self] in
            do {
                try await listener.run { networkConnection in
                    let peer = Self.peer(of: networkConnection)
                    // Charge before yielding. The handler blocks for the connection's whole lifetime,
                    // so the ticket is scoped exactly to it — no bookkeeping on the connection object.
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
            }
            catch {
                // `run` is the only place a bind refusal that never reaches a state update can surface;
                // a waiter parked in `waitUntilBound()` must see it rather than hang (CWE-755).
                self?.recordFailure(.bindFailed("cannot bind \(context): \(error)"))
            }
            continuation.finish()
        }
        runTask.withLock { $0 = task }
        do {
            try await waitUntilBound()
        }
        catch {
            // A refused bind must not leave `run` looping on a listener nobody owns: tear it down
            // before rethrowing, so a failed `start()` costs nothing beyond the error.
            await shutdown()
            throw error
        }
        return stream
    }

    /// Stops accepting: cancels the listener's run task, which unwinds it (the modern API has no
    /// `cancel()`; teardown is via structured task cancellation).
    public func shutdown() async {
        let task = runTask.withLock { current -> Task<Void, Never>? in
            let running = current
            current = nil
            return running
        }
        task?.cancel()
        // Drop the listener too. A `start()` that threw leaves a listener still parked in `run`
        // (a `.waiting` bind retries forever), and holding it keeps Network.framework's own queues
        // and sources alive for the life of the process. Not awaited: `run` unwinds on the
        // cancellation above, and awaiting it here would make teardown depend on it doing so.
        listenerBox.withLock { $0 = nil }
    }

    /// The address the peer of `connection` is speaking from.
    ///
    /// A QUIC connection is identified per peer (RFC 9000 §5.1).
    ///
    /// Read from `currentPath`, **not** from `NetworkConnection.remoteEndpoint`: on an inbound,
    /// listener-vended connection `remoteEndpoint` is `nil` (it reflects the endpoint a connection was
    /// *initialized to*, which an accepted connection never had), while `currentPath.remoteEndpoint`
    /// is the effective remote address and is already populated when `run`'s handler fires — verified
    /// against the SDK rather than assumed, because Apple documents neither property's inbound
    /// behaviour. `remoteEndpoint` is still consulted as a fallback in case that ever changes.
    private static func peer(
        of connection: Network.NetworkConnection<Network.QUIC>
    ) -> TransportAddress {
        QUICPeer.address(of: connection.currentPath?.remoteEndpoint ?? connection.remoteEndpoint)
    }

    /// Builds the listener, mapping a construction failure to the typed transport error.
    private static func makeListener(
        using builder: Network.NWParametersBuilder<Network.QUIC>
    ) throws(TransportError) -> Network.NetworkListener<Network.QUIC> {
        do {
            return try Network.NetworkListener(using: builder)
        }
        catch {
            throw TransportError.bindFailed("\(error)")
        }
    }

    /// Records a listener state transition: a realized port, a fatal bind refusal, or neither.
    ///
    /// A QUIC listener that cannot claim its configured local endpoint reports `.waiting` — not
    /// `.failed` — and stays there indefinitely (measured: RFC 5737 192.0.2.1 parks in
    /// `.waiting(EADDRNOTAVAIL)`). Only the unrecoverable `bind(2)` errors end the wait; a transient
    /// `.waiting` is still the listener's own business.
    private func handle(
        _ state: Network.NetworkListener<Network.QUIC>.State,
        of listener: Network.NetworkListener<Network.QUIC>,
        binding context: String
    ) {
        switch state {
            case .ready:
                let port = listener.port?.rawValue ?? 0
                bindState.withLock { current in
                    current.boundPort = port
                    current.waiter?.resume()
                    current.waiter = nil
                }
            case .failed(let error):
                recordFailure(
                    TransportError.bindFailure(from: error, binding: context)
                        ?? .bindFailed("cannot bind \(context): \(error)")
                )
            case .waiting(let error):
                guard let failure = TransportError.bindFailure(from: error, binding: context) else {
                    return
                }
                recordFailure(failure)
            case .setup, .cancelled:
                return
            @unknown default:
                return
        }
    }

    /// Latches a terminal bind failure and hands it to whoever is waiting on the bind.
    private func recordFailure(_ failure: TransportError) {
        bindState.withLock { current in
            guard current.boundPort == 0, current.failure == nil else {
                return
            }
            current.failure = failure
            current.waiter?.resume(throwing: failure)
            current.waiter = nil
        }
    }

    /// Suspends until the listener has claimed its configured endpoint, or throws why it cannot.
    private func waitUntilBound() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            bindState.withLock { current in
                if current.boundPort != 0 {
                    continuation.resume()
                }
                else if let failure = current.failure {
                    continuation.resume(throwing: failure)
                }
                else {
                    current.waiter = continuation
                }
            }
        }
    }
}
