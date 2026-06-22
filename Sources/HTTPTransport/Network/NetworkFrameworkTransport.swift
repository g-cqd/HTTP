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
    private let queue = DispatchQueue(label: "http.transport.network-framework")
    private let state = Mutex<State>(State())
    private let connectionIDs = ConnectionIDAllocator()

    private struct State {
        var listener: NWListener?
        var isReady = false
        var failure: TransportError?
        var readyContinuation: CheckedContinuation<Void, any Error>?
    }

    /// Creates a Network.framework transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    /// The actual bound port (meaningful after ``start()`` returns; resolves port `0` to the
    /// ephemeral port the OS chose).
    public var boundPort: UInt16 {
        state.withLock { $0.listener?.port?.rawValue ?? 0 }
    }

    /// Binds the listener and begins accepting, returning a stream of inbound connections.
    ///
    /// Waits for the listener to reach `ready` (so ``boundPort`` is valid) before returning.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        let listener = try makeListener()
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

        state.withLock { $0.listener = listener }
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

    // MARK: - Internals

    private func makeListener() throws -> NWListener {
        let port = NWEndpoint.Port(rawValue: configuration.port) ?? .any
        let parameters = try makeParameters()  // may throw TransportError.tlsConfigurationFailed
        do {
            return try NWListener(using: parameters, on: port)
        } catch {
            throw TransportError.bindFailed("\(error)")
        }
    }

    /// TLS `NWParameters` when ``TransportConfiguration/tls`` is set (advertising ALPN so a client can
    /// pick `"h2"`, RFC 9113 §3.3), otherwise a cleartext TCP listener (h1 / h2c).
    private func makeParameters() throws -> NWParameters {
        guard let tls = configuration.tls else { return .tcp }
        let identity = try NetworkFrameworkTLS.identity(
            pkcs12: tls.pkcs12, passphrase: tls.passphrase)
        let options = NetworkFrameworkTLS.options(
            identity: identity, applicationProtocols: tls.applicationProtocols,
            minVersion: tls.minVersion, maxVersion: tls.maxVersion)
        return NWParameters(tls: options)
    }

    private func handleNewConnection(
        _ nwConnection: NWConnection,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        let id = connectionIDs.next()
        // Surface the connection only once the handshake settles (`.ready`), so its negotiated ALPN
        // protocol (RFC 7301) is known and the server can commit to h2 vs h1 without sniffing. For a
        // cleartext listener `.ready` is just the completed TCP connect and ALPN resolves to nil.
        nwConnection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                nwConnection.stateUpdateHandler = nil
                let alpn = NetworkFrameworkTLS.negotiatedApplicationProtocol(of: nwConnection)
                continuation.yield(
                    NetworkFrameworkConnection(
                        id: id, connection: nwConnection, negotiatedApplicationProtocol: alpn))
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
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            state.withLock { current in
                if current.isReady {
                    continuation.resume()
                } else if let failure = current.failure {
                    continuation.resume(throwing: failure)
                } else {
                    current.readyContinuation = continuation
                }
            }
        }
    }
}
