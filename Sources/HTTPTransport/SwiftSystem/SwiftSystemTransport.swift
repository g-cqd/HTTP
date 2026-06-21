//
//  SwiftSystemTransport.swift
//  HTTPTransport
//
//  Backbone 2c — apple/swift-system typed descriptors over the POSIX socket syscalls. swift-system
//  exposes FileDescriptor (read/write/close) but not socket setup, so the listener is created with
//  the raw POSIX sockets API and accepted connections are wrapped in FileDescriptor.
//
//  Known limitation: blocking accept/read/write occupy worker threads, so under many
//  simultaneously-blocked connections this backbone overcommits the thread pool and degrades near
//  the pool ceiling. It exists to benchmark the blocking model against the event-driven backbones
//  (Network.framework, Dispatch, kqueue); it is not the high-concurrency default.
//
//  Standards: socket()/setsockopt()/bind()/listen()/accept()/getsockname() per POSIX.1-2017
//  (IEEE Std 1003.1-2017). The listener is a TCP (RFC 9293) stream socket over IPv4 (RFC 791).
//

internal import Darwin
internal import Dispatch
internal import Synchronization
internal import SystemPackage

/// The apple/swift-system transport backbone (typed FileDescriptor I/O over POSIX sockets).
///
/// Mutable state lives in a `Mutex` and the connection counter in an `Atomic`, so the type is
/// genuinely `Sendable` (no `@unchecked`). The blocking `accept()` runs on `acceptQueue`; each
/// connection serializes its I/O on a child of the shared `ioQueue` pool.
public final class SwiftSystemTransport: ServerTransport {

    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .swiftSystem

    private let configuration: TransportConfiguration
    private let acceptQueue = DispatchQueue(label: "http.transport.swift-system.accept")
    private let ioQueue = DispatchQueue(
        label: "http.transport.swift-system.io", attributes: .concurrent)
    private let state = Mutex<State>(State())
    private let connectionCounter = Atomic<UInt64>(0)

    private struct State {
        var listenDescriptor: FileDescriptor?
        var boundPort: UInt16 = 0
        var isRunning = false
    }

    private enum AcceptOutcome {
        case retry
        case stop
    }

    /// Creates a swift-system transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    /// The actual bound port (meaningful after ``start()`` returns).
    public var boundPort: UInt16 {
        state.withLock { $0.boundPort }
    }

    /// Binds a POSIX TCP listening socket and begins accepting, returning a stream of connections.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        let (descriptor, port) = try bindListenSocket()
        let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()
        state.withLock {
            $0.listenDescriptor = descriptor
            $0.boundPort = port
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

    /// Creates, binds (IPv4, RFC 791), and listens (TCP, RFC 9293) on a POSIX.1-2017 stream socket,
    /// returning the descriptor and the OS-assigned port.
    private func bindListenSocket() throws -> (FileDescriptor, UInt16) {
        let rawFD = socket(AF_INET, SOCK_STREAM, 0)
        guard rawFD >= 0 else { throw TransportError.bindFailed("socket() errno \(errno)") }

        var reuse: Int32 = 1
        _ = setsockopt(rawFD, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = configuration.port.bigEndian
        address.sin_addr.s_addr = in_addr_t(0x7f00_0001).bigEndian  // 127.0.0.1

        let bindStatus = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(rawFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindStatus == 0 else {
            let captured = errno
            close(rawFD)
            throw TransportError.bindFailed("bind() errno \(captured)")
        }
        guard listen(rawFD, 128) == 0 else {
            let captured = errno
            close(rawFD)
            throw TransportError.bindFailed("listen() errno \(captured)")
        }
        return (FileDescriptor(rawValue: rawFD), readBoundPort(of: rawFD))
    }

    /// Reads the OS-assigned port via getsockname() (POSIX.1-2017).
    private func readBoundPort(of rawFD: Int32) -> UInt16 {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(rawFD, $0, &length)
            }
        }
        return UInt16(bigEndian: address.sin_port)
    }

    private func acceptLoop(
        listenDescriptor: FileDescriptor,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        while state.withLock({ $0.isRunning }) {
            var address = sockaddr_in()
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientFD = withUnsafeMutablePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(listenDescriptor.rawValue, $0, &length)
                }
            }
            if clientFD < 0 {
                if case .stop = classifyAcceptError(errno) { break }
                continue
            }
            let id = TransportConnectionID(
                connectionCounter.wrappingAdd(1, ordering: .relaxed).newValue)
            continuation.yield(
                SwiftSystemConnection(
                    id: id,
                    descriptor: FileDescriptor(rawValue: clientFD),
                    peer: peerAddress(from: address),
                    targetQueue: ioQueue))
        }
        continuation.finish()
    }

    /// Decides whether an `accept()` failure is transient (retry) or terminal (stop) — so a single
    /// `EINTR`/`ECONNABORTED`, or fd exhaustion (`EMFILE`/`ENFILE`), cannot permanently kill the
    /// listener; only an actually-closed descriptor (`EBADF`/`EINVAL`) stops the loop.
    private func classifyAcceptError(_ error: Int32) -> AcceptOutcome {
        switch error {
        case EINTR, ECONNABORTED:
            return .retry
        case EMFILE, ENFILE:
            usleep(10_000)  // back off ~10 ms on fd exhaustion, then keep accepting
            return .retry
        default:
            return .stop  // EBADF / EINVAL (descriptor closed) or unrecoverable
        }
    }

    /// Resolves the peer's IPv4 address from the `sockaddr_in` filled by `accept()` (RFC 791).
    private func peerAddress(from address: sockaddr_in) -> TransportAddress {
        var source = address
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        withUnsafePointer(to: &source.sin_addr) { addressPointer in
            _ = inet_ntop(AF_INET, addressPointer, &buffer, socklen_t(INET_ADDRSTRLEN))
        }
        let host = String(
            decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return TransportAddress(host: host, port: UInt16(bigEndian: address.sin_port))
    }
}
