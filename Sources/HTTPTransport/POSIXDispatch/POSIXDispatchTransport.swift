//
//  POSIXDispatchTransport.swift
//  HTTPTransport
//
//  Backbone 3 — BSD sockets with GCD readiness. A non-blocking listening socket is watched by a
//  DispatchSource read source; each readiness event drains all pending connections with accept(),
//  and each connection is driven by a DispatchIO channel (kqueue under the hood, no hand-rolled
//  event loop).
//
//  Standards: socket()/bind()/listen()/accept() per POSIX.1-2017 (IEEE Std 1003.1-2017); the
//  listener is a TCP (RFC 9293) stream socket over IPv4 (RFC 791).
//

internal import Darwin
internal import Dispatch
internal import Synchronization

/// The BSD-sockets + GCD `DispatchSource`/`DispatchIO` transport backbone.
///
/// Mutable state lives in a `Mutex` and the connection counter in an `Atomic`, so the type is
/// `Sendable`. Accept readiness runs on `acceptQueue`; connection I/O runs on the shared `ioQueue`.
public final class POSIXDispatchTransport: ServerTransport {
    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .posixDispatch

    private let configuration: TransportConfiguration
    private let acceptQueue = DispatchQueue(label: "http.transport.posix-dispatch.accept")
    private let ioQueue = DispatchQueue(
        label: "http.transport.posix-dispatch.io",
        attributes: .concurrent
    )
    private let state = Mutex<State>(State())
    private let connectionIDs = ConnectionIDAllocator()

    private struct State {
        var acceptSource: (any DispatchSourceRead)?
        var boundPort: UInt16 = 0
        var isRunning = false
        /// The connection-stream continuation, finished on ``shutdown()`` so a consumer's `for await`
        /// completes instead of hanging.
        var continuation: AsyncStream<any TransportConnection>.Continuation?
    }

    /// Creates a Dispatch transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// The actual bound port (meaningful after ``start()`` returns).
    public var boundPort: UInt16 {
        state.withLock(\.boundPort)
    }

    /// Binds a non-blocking TCP socket and begins accepting via a read source.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        let listener = try POSIXSocket.makeListenSocket(
            host: configuration.host,
            port: configuration.port,
            nonBlocking: true,
            reusePort: configuration.reusePort,
            backlog: configuration.backlog
        )
        let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()

        let source = DispatchSource.makeReadSource(
            fileDescriptor: listener.descriptor,
            queue: acceptQueue
        )
        source.setEventHandler { [weak self] in
            self?.acceptPending(listenFD: listener.descriptor, continuation: continuation)
        }
        source.setCancelHandler {
            close(listener.descriptor)
        }
        state.withLock {
            $0.acceptSource = source
            $0.boundPort = listener.port
            $0.isRunning = true
            $0.continuation = continuation
        }
        continuation.onTermination = { [weak self] _ in
            Task { await self?.shutdown() }
        }
        source.resume()
        return stream
    }

    /// Cancels the read source (whose cancel handler closes the listening descriptor).
    public func shutdown() async {
        let (source, continuation) = state.withLock {
            let current = $0.acceptSource
            let cont = $0.continuation
            $0.acceptSource = nil
            $0.continuation = nil
            $0.isRunning = false
            return (current, cont)
        }
        // Finish the connection stream so a consumer's `for await` completes instead of hanging.
        continuation?.finish()
        source?.cancel()
    }

    // MARK: - Internals

    /// Drains every pending connection on a readiness event (a non-blocking socket is level- but
    /// drained edge-style to avoid repeated wakeups).
    private func acceptPending(
        listenFD: Int32,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        while state.withLock(\.isRunning) {
            var address = sockaddr_storage()
            var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let clientFD = withUnsafeMutablePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(listenFD, $0, &length)
                }
            }
            if clientFD < 0 {
                if case .retry = POSIXSocket.classifyAcceptError(errno) { continue }
                break  // wouldBlock (drained) or stop
            }
            POSIXSocket.setNonBlocking(clientFD)
            POSIXSocket.setNoSIGPIPE(clientFD)  // audit T-F1: a peer RST mid-write must not kill us
            POSIXSocket.setNoDelay(clientFD)  // disable Nagle — flush small responses now (p99.9)
            let id = connectionIDs.next()
            // A per-connection *serial* queue targeting the shared concurrent pool: it serializes this
            // connection's read/write readiness handling and close (so a close never races a syscall on
            // the fd), while still spreading connections across the pool's threads.
            let connectionQueue = DispatchQueue(
                label: "http.transport.posix-dispatch.conn",
                target: ioQueue
            )
            continuation.yield(
                POSIXDispatchConnection(
                    id: id,
                    descriptor: clientFD,
                    peer: POSIXSocket.peerAddress(from: address),
                    queue: connectionQueue
                )
            )
        }
    }
}
