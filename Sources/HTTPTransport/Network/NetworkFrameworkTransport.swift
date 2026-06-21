//
//  NetworkFrameworkTransport.swift
//  HTTPTransport
//
//  Backbone 1 — Apple Network.framework (NWListener / NWConnection): the path to TLS, ALPN, and
//  QUIC later. The async NetworkListener API is iOS 26+, so this uses the callback-based
//  NWListener/NWConnection (available at our floor) and bridges the accept loop to an AsyncStream.
//

internal import Foundation
internal import Network

/// The Network.framework transport backbone.
///
/// All mutable state is guarded by `lock`, and `NWListener`/`NWConnection` are documented
/// thread-safe, so the type is `@unchecked Sendable`. Listener state changes and inbound
/// connections (callback-driven on a dispatch queue) are bridged to `async`/`AsyncStream`.
public final class NetworkFrameworkTransport: ServerTransport, @unchecked Sendable {

    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .networkFramework

    private let configuration: TransportConfiguration
    private let queue = DispatchQueue(label: "http.transport.network-framework")

    private let lock = NSLock()
    private var listener: NWListener?
    private var nextID: UInt64 = 0
    private var isReady = false
    private var failure: TransportError?
    private var readyContinuation: CheckedContinuation<Void, any Error>?

    /// Creates a Network.framework transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    /// The actual bound port (meaningful after ``start()`` returns; resolves port `0` to the
    /// ephemeral port the OS chose).
    public var boundPort: UInt16 {
        withLock { listener?.port?.rawValue ?? 0 }
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

        withLock { self.listener = listener }
        listener.start(queue: queue)
        try await waitUntilReady()
        return stream
    }

    /// Cancels the listener and stops accepting.
    public func shutdown() async {
        let listener: NWListener? = withLock {
            let current = self.listener
            self.listener = nil
            return current
        }
        listener?.cancel()
    }

    // MARK: - Internals

    private func makeListener() throws -> NWListener {
        let port = NWEndpoint.Port(rawValue: configuration.port) ?? .any
        do {
            return try NWListener(using: .tcp, on: port)
        } catch {
            throw TransportError.bindFailed("\(error)")
        }
    }

    private func handleNewConnection(
        _ nwConnection: NWConnection,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        let id = withLock { () -> TransportConnectionID in
            nextID += 1
            return TransportConnectionID(nextID)
        }
        nwConnection.start(queue: queue)
        continuation.yield(NetworkFrameworkConnection(id: id, connection: nwConnection))
    }

    private func handleStateChange(
        _ newState: NWListener.State,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        withLock {
            switch newState {
            case .ready:
                isReady = true
                readyContinuation?.resume()
                readyContinuation = nil
            case .failed(let error):
                let failure = TransportError.bindFailed("\(error)")
                self.failure = failure
                readyContinuation?.resume(throwing: failure)
                readyContinuation = nil
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
            withLock {
                if isReady {
                    continuation.resume()
                } else if let failure {
                    continuation.resume(throwing: failure)
                } else {
                    readyContinuation = continuation
                }
            }
        }
    }

    private func withLock<R>(_ body: () -> R) -> R {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
