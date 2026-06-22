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
        label: "http.transport.posix-dispatch.io", attributes: .concurrent)
    private let state = Mutex<State>(State())
    private let connectionIDs = ConnectionIDAllocator()

    private struct State {
        var acceptSource: (any DispatchSourceRead)?
        var boundPort: UInt16 = 0
        var isRunning = false
    }

    /// Creates a Dispatch transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    /// The actual bound port (meaningful after ``start()`` returns).
    public var boundPort: UInt16 {
        state.withLock { $0.boundPort }
    }

    /// Binds a non-blocking TCP socket and begins accepting via a read source.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        let listener = try POSIXSocket.makeListenSocket(
            host: configuration.host, port: configuration.port, nonBlocking: true)
        let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()

        let source = DispatchSource.makeReadSource(
            fileDescriptor: listener.descriptor, queue: acceptQueue)
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
        }
        continuation.onTermination = { [weak self] _ in
            Task { await self?.shutdown() }
        }
        source.resume()
        return stream
    }

    /// Cancels the read source (whose cancel handler closes the listening descriptor).
    public func shutdown() async {
        let source: (any DispatchSourceRead)? = state.withLock {
            let current = $0.acceptSource
            $0.acceptSource = nil
            $0.isRunning = false
            return current
        }
        source?.cancel()
    }

    // MARK: - Internals

    /// Drains every pending connection on a readiness event (a non-blocking socket is level- but
    /// drained edge-style to avoid repeated wakeups).
    private func acceptPending(
        listenFD: Int32,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        while state.withLock({ $0.isRunning }) {
            var address = sockaddr_in()
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
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
            let id = connectionIDs.next()
            let channel = DispatchIO(type: .stream, fileDescriptor: clientFD, queue: ioQueue) { _ in
                close(clientFD)
            }
            // Deliver bytes as soon as ≥1 is available, rather than buffering to the read length —
            // otherwise a `read(length:)` blocks until the buffer fills or the peer half-closes.
            channel.setLimit(lowWater: 1)
            continuation.yield(
                POSIXDispatchConnection(
                    id: id, channel: channel,
                    peer: POSIXSocket.peerAddress(from: address), queue: ioQueue))
        }
    }
}
