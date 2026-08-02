//
//  NetworkFrameworkTransport.swift
//  HTTPTransport
//
//  Backbone 1 — Apple Network.framework (NWListener / NWConnection): the path to TLS, ALPN, and
//  QUIC later. The async NetworkListener API is iOS 26+, so this uses the callback-based
//  NWListener/NWConnection (available at our floor) and bridges the accept loop to an AsyncStream.
//
//  Standards: NWListener/NWConnection implement TCP (RFC 9293) over IP (RFC 791/8200); the later
//  secure path is TLS 1.3 (RFC 8446) and QUIC (RFC 9000).
//

internal import Foundation
internal import Network
internal import Synchronization

/// The Network.framework transport backbone.
///
/// Mutable state lives in a `Mutex` and the connection counter in an `Atomic`, so the type is
/// genuinely `Sendable` (no `@unchecked`). Listener state changes and inbound connections
/// (callback-driven on a dispatch queue) are bridged to `async`/`AsyncStream`.
public final class NetworkFrameworkTransport: ServerTransport {
    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .networkFramework

    private let configuration: TransportConfiguration
    // `.userInitiated` so NWConnection/NWListener callbacks are scheduled promptly under contention.
    private let queue = DispatchQueue(
        label: "http.transport.network-framework",
        qos: .userInitiated
    )
    private let state = Mutex<State>(State())
    private let connectionIDs = ConnectionIDAllocator()

    private struct State {
        var listener: NWListener?
        var isReady = false
        var failure: TransportError?
        var readyContinuation: UnsafeContinuation<Void, any Error>?
        /// The bound port captured at the `.ready` transition (RFC-agnostic; NF assigns the ephemeral
        /// port by then), so reads never race a live `listener.port` that can be transiently nil under
        /// concurrent load.
        var boundPort: UInt16 = 0
        /// The local endpoint the configuration resolved to, captured at ``start(admission:)`` so a
        /// ``reload(tls:)`` rebinds the *same* interface rather than re-deriving it (audit F-05).
        var bindEndpoint: BindEndpoint?
        /// The currently-active TLS identity (`nil` for a cleartext listener), swapped by
        /// ``reload(tls:)`` (G4b). `makeParameters` reads it so a rebuilt listener picks up the new
        /// identity; `handleNewConnection` reads it to mark accepted connections secure.
        var tls: TransportTLS?
        /// The inbound-connection stream continuation, captured at ``start()`` so a reloaded listener's
        /// `newConnectionHandler` can yield into the same stream the server is already consuming.
        var continuation: AsyncStream<any TransportConnection>.Continuation?
        /// The admission policy applied when a connection is delivered, *before* the handshake
        /// completes and before anything is yielded (audit F8); ungated until ``start(admission:)``.
        var gate = AcceptGate(admission: nil)
    }

    /// Creates a Network.framework transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// The actual bound port (meaningful after ``start()`` returns; resolves port `0` to the
    /// ephemeral port the OS chose).
    ///
    /// Returns the value captured at the listener's `.ready` transition; falls back to a live
    /// `listener.port` read only if that capture is somehow still 0 (belt-and-suspenders).
    public var boundPort: UInt16 {
        state.withLock { $0.boundPort != 0 ? $0.boundPort : ($0.listener?.port?.rawValue ?? 0) }
    }

    /// The local endpoint actually bound — the resolved interface literal plus the realized port.
    ///
    /// `nil` before ``start(admission:)`` binds. This is what an operator (and a `Alt-Svc`
    /// advertisement, RFC 7838) should report: the configured host may have been a name or a
    /// wildcard, and the configured port may have been the ephemeral `0`.
    public var boundEndpoint: BindEndpoint? {
        state.withLock { current in
            guard let endpoint = current.bindEndpoint, current.boundPort != 0 else {
                return nil
            }
            return BindEndpoint(
                address: endpoint.address,
                family: endpoint.family,
                port: current.boundPort
            )
        }
    }

    /// Binds the listener and begins accepting, returning a stream of inbound connections.
    ///
    /// Waits for the listener to reach `ready` (so ``boundPort`` is valid) before returning. The
    /// configured host is resolved to a concrete local endpoint *here*, once, and applied to the
    /// listener's parameters — a bind that cannot be satisfied throws ``TransportError/bindFailed(_:)``
    /// rather than silently landing on another interface (audit F-05).
    public func start(
        admission: ConnectionAdmission?
    ) async throws -> AsyncStream<any TransportConnection> {
        let endpoint = try BindEndpoint.resolve(configuration)
        let listener = try makeListener(tls: configuration.tls, endpoint: endpoint)
        let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()

        listener.newConnectionHandler = { [weak self] nwConnection in
            self?.handleNewConnection(nwConnection, continuation: continuation)
        }
        listener.stateUpdateHandler = { [weak self] newState in
            self?.handleStateChange(newState, continuation: continuation)
        }
        continuation.onTermination = { [weak self] _ in
            Task { await self?.shutdown() }
        }

        // Record the initial identity and the stream continuation so ``reload(tls:)`` can rebuild the
        // listener and feed new connections into this same stream.
        state.withLock {
            $0.tls = configuration.tls
            $0.continuation = continuation
            $0.listener = listener
            $0.bindEndpoint = endpoint
            $0.gate = AcceptGate(admission: admission)
        }
        // `NWListener` has no suspend, but `newConnectionLimit` is exactly the equivalent knob: at zero
        // "new connections will be queued and eventually blocked, until you raise the limit". The gate's
        // hysteresis resume raises it back to infinite.
        admission?
            .onResume { [weak self] in
                // Onto the listener's own queue: the resume runs on whichever thread released the
                // deciding slot, and every other `NWListener` interaction happens here.
                //
                // Bound strongly first: nesting a second `self?.` inside the hop would capture the
                // outer optional binding itself, which the compiler reads as a captured `var` in
                // concurrently-executing code.
                guard let self else {
                    return
                }
                queue.async { [self] in setConnectionLimit(NWListener.InfiniteConnectionLimit) }
            }
        listener.start(queue: queue)
        try await waitUntilReady()
        return stream
    }

    /// Cancels the listener, stops accepting, and waits for the bound port to be released.
    ///
    /// `NWListener.cancel()` is asynchronous: it returns long before the listener reaches `.cancelled`
    /// and gives the port back. A `shutdown()` that returned at `cancel()` made "stop, then restart on
    /// the same configured port" a race the restart lost with `EADDRINUSE` — so the wait is part of the
    /// contract, not an optimization. The same `.cancelled` await already guards the reload path.
    public func shutdown() async {
        let listener: NWListener? = state.withLock {
            let current = $0.listener
            $0.listener = nil
            $0.isReady = false
            $0.boundPort = 0
            return current
        }
        guard let listener else {
            return
        }
        await retireListener(listener)
        state.withLock { $0.continuation?.finish() }
    }

    /// Hot-reloads the TLS identity (G4b): rebinds the listener with `tls` on the same port, so new
    /// handshakes use the new identity while already-accepted connections keep serving on the old one.
    ///
    /// Restart-based, because Network.framework's challenge block is *client*-side and the server
    /// identity is fixed at listen time. `NWListener` cannot share a bound port (SO_REUSEADDR is not
    /// enough — that needs SO_REUSEPORT, which `NWListener` does not expose), so the old listener is
    /// fully retired — its `.cancelled` awaited so the port is released — before the replacement binds
    /// the freed port. That is a brief accept gap for *new* connections, but already-accepted
    /// `NWConnection`s are independent of the listener and keep serving (zero existing-connection
    /// drops). A bad identity throws before the running listener is touched.
    public func reload(tls: TransportTLS) async throws {
        // The transport must be accepting: capture the bound endpoint and the live stream continuation.
        let (endpoint, continuation) = try state.withLock {
            current -> (BindEndpoint, AsyncStream<any TransportConnection>.Continuation) in
            guard current.boundPort != 0, let bound = current.bindEndpoint,
                let continuation = current.continuation
            else {
                throw TransportError.closed
            }
            // Rebind the same *interface* as well as the same port: re-resolving the configured host
            // could land elsewhere if DNS moved under us, and dropping the host would widen the
            // reloaded listener to every interface (audit F-05).
            let sameEndpoint = BindEndpoint(
                address: bound.address,
                family: bound.family,
                port: current.boundPort
            )
            return (sameEndpoint, continuation)
        }
        // Build the replacement (and its identity) first, so a bad identity throws here with the
        // running listener untouched.
        let newListener = try makeListener(tls: tls, endpoint: endpoint)
        newListener.newConnectionHandler = { [weak self] nwConnection in
            self?.handleNewConnection(nwConnection, continuation: continuation)
        }
        // Promote the replacement + identity to current, retire the old listener (awaiting its full
        // cancel so the port frees), then bind the replacement on the freed port.
        let oldListener = state.withLock { current -> NWListener? in
            let previous = current.listener
            current.listener = newListener
            current.tls = tls
            // Carry the accept ceiling across the swap: a replacement listener starts unlimited, so a
            // reload while the gate is saturated would silently re-open the tap (audit F8).
            newListener.newConnectionLimit =
                current.gate.admission?.isSaturated == true
                ? 0 : NWListener.InfiniteConnectionLimit
            return previous
        }
        if let oldListener {
            await retireListener(oldListener)
        }
        try await startReplacement(newListener, endpoint: endpoint, continuation: continuation)
    }

    // MARK: - Internals

    /// Cancels `listener` and waits for it to reach `.cancelled` (releasing its bound port) *without*
    /// finishing the shared stream — so a reload's replacement can bind the freed port.
    private func retireListener(_ listener: NWListener) async {
        // No throw is possible; `try?` only discards the continuation's `Error` channel.
        try? await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
            let resumer = OnceResumer(continuation)
            listener.stateUpdateHandler = { newState in
                switch newState {
                    case .cancelled, .failed:
                        resumer.resume(returning: ())
                    default:
                        break
                }
            }
            listener.cancel()
        }
    }

    /// Starts a replacement listener and waits for it to reach `.ready` (so it is accepting).
    ///
    /// Its handler also finishes the shared stream on `.failed`/`.cancelled`, so a later shutdown or
    /// fault of the now-current listener tears the stream down as usual.
    private func startReplacement(
        _ listener: NWListener,
        endpoint: BindEndpoint,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) async throws {
        try await withUnsafeThrowingContinuation {
            (ready: UnsafeContinuation<Void, any Error>) in
            let resumer = OnceResumer(ready)
            let context = endpoint.description
            listener.stateUpdateHandler = { newState in
                switch newState {
                    case .ready:
                        resumer.resume(returning: ())
                    case .failed(let error):
                        resumer.resume(throwing: TransportError.bindFailed("\(error)"))
                        continuation.finish()
                    case .waiting(let error):
                        // A required local endpoint that can never be claimed parks the listener in
                        // `.waiting` forever; only then is waiting a failure (audit F-05).
                        let bindFailure = TransportError.bindFailure(from: error, binding: context)
                        guard let failure = bindFailure else {
                            break
                        }
                        resumer.resume(throwing: failure)
                        continuation.finish()
                    case .cancelled:
                        continuation.finish()
                    default:
                        break
                }
            }
            listener.start(queue: queue)
        }
    }

    /// Builds an `NWListener` pinned to `endpoint` — the configured host *and* port, not the port alone.
    ///
    /// The local endpoint travels on `NWParameters.requiredLocalEndpoint`, which is the mechanism
    /// available at this package's macOS 15.6 / iOS 18 floor (the typed `localEndpoint(_:)` builder is
    /// macOS 26+). `NWListener(using:on:)`'s `on:` port is deliberately left at its `.any` default: the
    /// port belongs to the required endpoint, so there is exactly one place a port can come from.
    private func makeListener(tls: TransportTLS?, endpoint: BindEndpoint) throws -> NWListener {
        let parameters = try makeParameters(tls: tls)  // may throw .tlsConfigurationFailed
        parameters.requiredLocalEndpoint = try endpoint.networkEndpoint()
        do {
            return try NWListener(using: parameters)
        }
        catch {
            throw TransportError.bindFailed("\(error)")
        }
    }

    /// TLS `NWParameters` when `tls` is set (advertising ALPN so a client can pick `"h2"`, RFC 9113
    /// §3.3), otherwise a cleartext TCP listener (h1 / h2c).
    ///
    /// Takes the identity as an argument (rather than reading the immutable `configuration.tls`) so
    /// ``reload(tls:)`` (G4b) can rebuild the listener with a fresh identity. `allowLocalEndpointReuse`
    /// (SO_REUSEADDR) lets the reloaded listener bind the same port while the old one is still
    /// draining, so the accept gap during a hot cert reload is minimal.
    private func makeParameters(tls: TransportTLS?) throws -> NWParameters {
        // Disable Nagle's algorithm so a sub-MSS response flushes immediately instead of waiting to
        // coalesce — Nagle + delayed-ACK inflates the tail latency the Bench/ comparison exposed.
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let parameters: NWParameters
        if let tls {
            // PEM identities need the portable backbone: Security offers no public in-memory
            // certificate + key → SecIdentity constructor (SecIdentityRef comes only from
            // SecPKCS12Import or a keychain query, and a keychain import breaks headless daemons) —
            // fail closed at start() rather than mis-load an empty PKCS#12.
            guard tls.pemIdentity == nil else {
                throw TransportError.tlsConfigurationFailed(
                    "PEM identities require the portable TLS backbone (HTTP_PORTABLE_TLS); "
                        + "Network.framework loads identities from PKCS#12 only"
                )
            }
            let identity = try NetworkFrameworkTLS.identity(
                pkcs12: tls.pkcs12,
                passphrase: tls.passphrase
            )
            // `options` rejects `.optional` client-auth (Network.framework can't request-but-don't-
            // require) with `.unsupported`, so an `.optional` listener on this backbone fails closed at
            // `start()` instead of silently degrading to one-way TLS (it needs the portable backbone).
            let options = try NetworkFrameworkTLS.options(
                identity: identity,
                applicationProtocols: tls.applicationProtocols,
                minVersion: tls.minVersion,
                maxVersion: tls.maxVersion,
                clientAuth: tls.clientAuth,
                verifyPeer: tls.verifyPeer
            )
            parameters = NWParameters(tls: options, tcp: tcp)
        }
        else {
            parameters = NWParameters(tls: nil, tcp: tcp)  // cleartext TCP (h1 / h2c)
        }
        // `allowLocalEndpointReuse` is Network.framework's *port-sharing* switch, not the plain
        // SO_REUSEADDR the POSIX backbones always set: with it on at both ends, a second listener binds
        // a port a first one already holds and the two silently share it (measured — see
        // `portConflictFailsClosed`). That is the accidental-second-instance hazard POSIXSocket
        // deliberately keeps behind `reusePort`, so it is gated on the same flag here. A prefork worker
        // opts in; anything else fails closed with `EADDRINUSE`.
        parameters.allowLocalEndpointReuse = configuration.reusePort
        return parameters
    }

    /// Charges an admission slot for a delivered connection, then surfaces it once its handshake
    /// settles.
    ///
    /// The charge happens **here** — when Network.framework delivers the connection, before it is
    /// started and long before `.ready` — so a peer that completes the TCP connect and then stalls the
    /// TLS handshake still holds a slot against the ceiling (audit F8). The stream stays `.unbounded`
    /// deliberately: `AsyncStream`'s buffering policy *drops* on overflow, and a dropped connection is
    /// a leaked `NWConnection`, strictly worse than the queue depth it would bound. The bound comes
    /// from the gate, because a slot is charged before `yield`.
    private func handleNewConnection(
        _ nwConnection: NWConnection,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        // Read the active identity (swappable by reload, G4b): a TLS listener advertised ALPN, enforced
        // below. Once per accept, off the byte path.
        let (gate, isSecure) = state.withLock { ($0.gate, $0.tls != nil) }
        let peer = NetworkFrameworkConnection.address(of: nwConnection.endpoint)
        let ticket: AdmissionTicket?
        // There is no descriptor to close on this backbone — cancelling the `NWConnection` is the
        // refusal, and it happens before the connection is ever started.
        let refuse: (Int32) -> Void = { _ in nwConnection.cancel() }
        switch gate.admit(descriptor: -1, host: peer.host, close: refuse) {
            case .rejectedContinue:
                return
            case .saturatedStop:
                setConnectionLimit(0)
                return
            case .admit(let charged, let saturated):
                ticket = charged
                if saturated {
                    setConnectionLimit(0)  // that was the last slot — stop delivering
                }
        }
        let id = connectionIDs.next()
        // Surface the connection only once the handshake settles (`.ready`), so its negotiated ALPN
        // protocol (RFC 7301) is known and the server can commit to h2 vs h1 without sniffing. For a
        // cleartext listener `.ready` is just the completed TCP connect and ALPN resolves to nil.
        nwConnection.stateUpdateHandler = { state in
            switch state {
                case .ready:
                    nwConnection.stateUpdateHandler = nil
                    let alpn = NetworkFrameworkTLS.negotiatedApplicationProtocol(of: nwConnection)
                    // Capture the verified client-cert identity (mutual TLS, G3: DER chain + subject
                    // + SANs) on the NW queue, where the handshake metadata is settled — nil unless
                    // this is a `.required` client-auth listener and the peer presented an accepted
                    // certificate.
                    let peerIdentity = NetworkFrameworkTLS.peerIdentity(of: nwConnection)
                    continuation.yield(
                        NetworkFrameworkConnection(
                            id: id,
                            connection: nwConnection,
                            negotiatedApplicationProtocol: alpn,
                            isSecure: isSecure,
                            tlsPeerIdentity: peerIdentity,
                            admissionTicket: ticket
                        )
                    )
                case .failed, .cancelled:
                    nwConnection.stateUpdateHandler = nil
                    nwConnection.cancel()
                    // The handshake never settled, so nothing downstream owns the slot: return it now
                    // rather than waiting for the ticket's `deinit`.
                    ticket?.release()
                default:
                    break
            }
        }
        nwConnection.start(queue: queue)
    }

    /// Sets the live listener's `newConnectionLimit` — `0` to stop delivering, infinite to resume.
    ///
    /// `NWListener` exposes no suspend; this is the documented equivalent, and it is reversible: at
    /// zero, inbound connections queue and are eventually blocked until the limit is raised again.
    /// **Must be called on ``queue``** — from the new-connection handler it is applied synchronously,
    /// so the limit lands before the framework delivers the next connection rather than one handler
    /// later (which would refuse a connection that the backlog should have held).
    private func setConnectionLimit(_ limit: Int) {
        state.withLock(\.listener)?.newConnectionLimit = limit
    }

    private func handleStateChange(
        _ newState: NWListener.State,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        state.withLock { current in
            switch newState {
                case .ready:
                    current.isReady = true
                    // Capture the now-bound ephemeral port on the NW queue, where `.ready` guarantees
                    // it is assigned, so later cross-thread reads don't race a transient nil.
                    current.boundPort = current.listener?.port?.rawValue ?? 0
                    current.readyContinuation?.resume()
                    current.readyContinuation = nil
                case .failed(let error):
                    fail(&current, with: TransportError.bindFailed("\(error)"), continuation)
                case .waiting(let error):
                    // `.waiting` is normally transient and self-healing, but a required local endpoint
                    // no interface owns parks the listener here permanently — `start()` would never
                    // return and the server would come up bound to nothing (audit F-05, CWE-755).
                    let context = current.bindEndpoint?.description ?? "the configured endpoint"
                    guard let failure = TransportError.bindFailure(from: error, binding: context)
                    else {
                        break
                    }
                    fail(&current, with: failure, continuation)
                case .cancelled:
                    continuation.finish()
                default:
                    break
            }
        }
    }

    /// Records a terminal listener failure, unblocks ``waitUntilReady()``, and finishes the stream.
    private func fail(
        _ current: inout State,
        with failure: TransportError,
        _ continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        current.failure = failure
        current.readyContinuation?.resume(throwing: failure)
        current.readyContinuation = nil
        continuation.finish()
    }

    private func waitUntilReady() async throws {
        try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
            state.withLock { current in
                if current.isReady {
                    continuation.resume()
                }
                else if let failure = current.failure {
                    continuation.resume(throwing: failure)
                }
                else {
                    current.readyContinuation = continuation
                }
            }
        }
    }
}
