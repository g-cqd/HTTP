//
//  SwiftSystemTransport.swift
//  HTTPTransport
//
//  Backbone 2 — apple/swift-system typed descriptors over the POSIX socket syscalls. swift-system
//  exposes FileDescriptor (read/write/close) but not socket setup, so the listener is created via
//  the shared `POSIXSocket` helper and accepted connections are wrapped in FileDescriptor.
//
//  Known limitation: blocking accept/read/write occupy worker threads, so under many
//  simultaneously-blocked connections this backbone overcommits the thread pool and degrades near
//  the pool ceiling. It exists to benchmark the blocking model against the event-driven backbones
//  (Network.framework, Dispatch, kqueue); it is not the high-concurrency default.
//
//  Standards: TCP (RFC 9293) over IPv4 (RFC 791) via POSIX.1-2017 (IEEE Std 1003.1-2017) sockets.
//

internal import Darwin
internal import Dispatch
internal import Synchronization
internal import SystemPackage

/// The apple/swift-system transport backbone (typed FileDescriptor I/O over POSIX sockets).
///
/// Mutable state lives in a `Mutex` and the connection counter in an `Atomic`, so the type is
/// `Sendable`. The blocking `accept()` runs on `acceptQueue`; each connection serializes its I/O on
/// a child of the shared `ioQueue` pool.
public final class SwiftSystemTransport: ServerTransport {
    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .swiftSystem

    private let configuration: TransportConfiguration
    private let acceptQueue = DispatchQueue(label: "http.transport.swift-system.accept")
    private let ioQueue = DispatchQueue(
        label: "http.transport.swift-system.io",
        attributes: .concurrent
    )
    private let state = Mutex<State>(State())
    private let connectionIDs = ConnectionIDAllocator()

    private struct State {
        var listenDescriptor: FileDescriptor?
        var boundPort: UInt16 = 0
        var isRunning = false
    }

    /// Creates a swift-system transport for `configuration`.
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

    /// Binds a POSIX TCP listening socket and begins accepting, returning a stream of connections.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        let listener = try POSIXSocket.makeListenSocket(
            host: configuration.host,
            port: configuration.port,
            nonBlocking: false,
            reusePort: configuration.reusePort,
            backlog: configuration.backlog
        )
        let descriptor = FileDescriptor(rawValue: listener.descriptor)
        let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()
        state.withLock {
            $0.listenDescriptor = descriptor
            $0.boundPort = listener.port
            $0.isRunning = true
        }
        continuation.onTermination = { [weak self] _ in
            Task { await self?.shutdown() }
        }
        acceptQueue.async { [weak self] in
            self?.acceptLoop(listenDescriptor: descriptor, continuation: continuation)
        }
        return stream
    }

    /// Closes the listening socket, which unblocks and ends the accept loop.
    public func shutdown() async {
        let descriptor: FileDescriptor? = state.withLock {
            let current = $0.listenDescriptor
            $0.listenDescriptor = nil
            $0.isRunning = false
            return current
        }
        try? descriptor?.close()
    }

    // MARK: - Internals

    private func acceptLoop(
        listenDescriptor: FileDescriptor,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        drain: while state.withLock(\.isRunning) {
            var address = sockaddr_storage()
            var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let clientFD = withUnsafeMutablePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(listenDescriptor.rawValue, $0, &length)
                }
            }
            if clientFD < 0 {
                switch POSIXSocket.classifyAcceptError(errno) {
                    case .retry:
                        continue
                    case .backoff:
                        // fd exhaustion: this loop owns a dedicated accept thread (no connection I/O
                        // runs on it), so a brief sleep is the right backoff — it delays only new
                        // accepts, never live traffic (audit F-EMFILE).
                        usleep(useconds_t(POSIXSocket.acceptBackoffMilliseconds * 1_000))
                        continue
                    case .wouldBlock, .stop:
                        // A closed descriptor (shutdown) or an unrecoverable error stops the loop.
                        break drain
                }
            }
            POSIXSocket.setNoSIGPIPE(clientFD)  // audit T-F1: a peer RST mid-write must not kill us
            POSIXSocket.setNoDelay(clientFD)  // disable Nagle — flush small responses now (p99.9)
            let id = connectionIDs.next()
            continuation.yield(
                SwiftSystemConnection(
                    id: id,
                    descriptor: FileDescriptor(rawValue: clientFD),
                    peer: POSIXSocket.peerAddress(from: address),
                    targetQueue: ioQueue
                )
            )
        }
        continuation.finish()
    }
}
