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
        /// The currently-active TLS identity (`nil` for a cleartext listener), swapped by
        /// ``reload(tls:)`` (G4b). `makeParameters` reads it so a rebuilt listener picks up the new
        /// identity; `handleNewConnection` reads it to mark accepted connections secure.
        var tls: TransportTLS?
        /// The inbound-connection stream continuation, captured at ``start()`` so a reloaded listener's
        /// `newConnectionHandler` can yield into the same stream the server is already consuming.
        var continuation: AsyncStream<any TransportConnection>.Continuation?
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

    /// Binds the listener and begins accepting, returning a stream of inbound connections.
    ///
    /// Waits for the listener to reach `ready` (so ``boundPort`` is valid) before returning.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        let listener = try makeListener(tls: configuration.tls, port: configuration.port)
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
        }
        listener.start(queue: queue)
        try await waitUntilReady()
        return stream
    }

    /// Cancels the listener and stops accepting.
    public func shutdown() async {
        let listener: NWListener? = state.withLock {
            let current = $0.listener
            $0.listener = nil
            return current
        }
        listener?.cancel()
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
        // The transport must be accepting: capture the bound port and the live stream continuation.
        let (port, continuation) = try state.withLock {
            current -> (UInt16, AsyncStream<any TransportConnection>.Continuation) in
            guard current.boundPort != 0, let continuation = current.continuation else {
                throw TransportError.closed
            }
            return (current.boundPort, continuation)
        }
        // Build the replacement (and its identity) first, so a bad identity throws here with the
        // running listener untouched.
        let newListener = try makeListener(tls: tls, port: port)
        newListener.newConnectionHandler = { [weak self] nwConnection in
            self?.handleNewConnection(nwConnection, continuation: continuation)
        }
        // Promote the replacement + identity to current, retire the old listener (awaiting its full
        // cancel so the port frees), then bind the replacement on the freed port.
        let oldListener = state.withLock { current -> NWListener? in
            let previous = current.listener
            current.listener = newListener
            current.tls = tls
            return previous
        }
        if let oldListener {
            await retireListener(oldListener)
        }
        try await startReplacement(newListener, continuation: continuation)
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
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) async throws {
        try await withUnsafeThrowingContinuation {
            (ready: UnsafeContinuation<Void, any Error>) in
            let resumer = OnceResumer(ready)
            listener.stateUpdateHandler = { newState in
                switch newState {
                    case .ready:
                        resumer.resume(returning: ())
                    case .failed(let error):
                        resumer.resume(throwing: TransportError.bindFailed("\(error)"))
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

    private func makeListener(tls: TransportTLS?, port: UInt16) throws -> NWListener {
        let endpointPort = NWEndpoint.Port(rawValue: port) ?? .any
        let parameters = try makeParameters(tls: tls)  // may throw .tlsConfigurationFailed
        do {
            return try NWListener(using: parameters, on: endpointPort)
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
        parameters.allowLocalEndpointReuse = true
        return parameters
    }

    private func handleNewConnection(
        _ nwConnection: NWConnection,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        let id = connectionIDs.next()
        // Read the active identity (swappable by reload, G4b): a TLS listener advertised ALPN, enforced
        // below. Once per accept, off the byte path.
        let isSecure = state.withLock { $0.tls != nil }
        // Surface the connection only once the handshake settles (`.ready`), so its negotiated ALPN
        // protocol (RFC 7301) is known and the server can commit to h2 vs h1 without sniffing. For a
        // cleartext listener `.ready` is just the completed TCP connect and ALPN resolves to nil.
        nwConnection.stateUpdateHandler = { state in
            switch state {
                case .ready:
                    nwConnection.stateUpdateHandler = nil
                    let alpn = NetworkFrameworkTLS.negotiatedApplicationProtocol(of: nwConnection)
                    // Capture the verified client-cert subject (mutual TLS) on the NW queue, where the
                    // handshake metadata is settled — nil unless this is a `.required` client-auth
                    // listener and the peer presented an accepted certificate.
                    let peerSubject = NetworkFrameworkTLS.peerSubject(of: nwConnection)
                    continuation.yield(
                        NetworkFrameworkConnection(
                            id: id,
                            connection: nwConnection,
                            negotiatedApplicationProtocol: alpn,
                            isSecure: isSecure,
                            tlsPeerSubject: peerSubject
                        )
                    )
                case .failed, .cancelled:
                    nwConnection.stateUpdateHandler = nil
                    nwConnection.cancel()
                default:
                    break
            }
        }
        nwConnection.start(queue: queue)
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
                    let failure = TransportError.bindFailed("\(error)")
                    current.failure = failure
                    current.readyContinuation?.resume(throwing: failure)
                    current.readyContinuation = nil
                    continuation.finish()
                case .cancelled:
                    continuation.finish()
                default:
                    break
            }
        }
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
