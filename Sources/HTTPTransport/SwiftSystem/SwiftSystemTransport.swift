//
//  SwiftSystemTransport.swift
//  HTTPTransport
//
//  Backbone 2c — apple/swift-system typed descriptors over the POSIX socket syscalls. swift-system
//  exposes FileDescriptor (read/write/close) but not socket setup, so the listener is created with
//  the raw POSIX sockets API and accepted connections are wrapped in FileDescriptor.
//
//  Standards: socket()/setsockopt()/bind()/listen()/accept()/getsockname() per POSIX.1-2017
//  (IEEE Std 1003.1-2017). The listener is a TCP (RFC 9293) stream socket over IPv4 (RFC 791).
//

internal import Darwin
internal import Dispatch
internal import Foundation
internal import SystemPackage

/// The apple/swift-system transport backbone (typed FileDescriptor I/O over POSIX sockets).
///
/// All mutable state is guarded by `lock`; the blocking `accept()` runs on `acceptQueue` and
/// per-connection blocking `read`/`write` on `ioQueue`. `@unchecked Sendable` for that lock-guarded
/// state.
public final class SwiftSystemTransport: ServerTransport, @unchecked Sendable {

    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .swiftSystem

    private let configuration: TransportConfiguration
    private let acceptQueue = DispatchQueue(label: "http.transport.swift-system.accept")
    private let ioQueue = DispatchQueue(
        label: "http.transport.swift-system.io", attributes: .concurrent)
    private let lock = NSLock()
    private var listenDescriptor: FileDescriptor?
    private var boundPortValue: UInt16 = 0
    private var nextID: UInt64 = 0
    private var running = false

    /// Creates a swift-system transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    /// The actual bound port (meaningful after ``start()`` returns).
    public var boundPort: UInt16 {
        withLock { boundPortValue }
    }

    /// Binds a POSIX TCP listening socket and begins accepting, returning a stream of connections.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        let (descriptor, port) = try bindListenSocket()
        let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()
        withLock {
            listenDescriptor = descriptor
            boundPortValue = port
            running = true
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
        let descriptor: FileDescriptor? = withLock {
            let current = listenDescriptor
            listenDescriptor = nil
            running = false
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
        while withLock({ running }) {
            let clientFD = accept(listenDescriptor.rawValue, nil, nil)
            guard clientFD >= 0 else { break }  // listen socket closed on shutdown
            let id = withLock { () -> TransportConnectionID in
                nextID += 1
                return TransportConnectionID(nextID)
            }
            continuation.yield(
                SwiftSystemConnection(
                    id: id,
                    descriptor: FileDescriptor(rawValue: clientFD),
                    peer: TransportAddress(host: configuration.host, port: 0),
                    ioQueue: ioQueue))
        }
        continuation.finish()
    }

    private func withLock<R>(_ body: () -> R) -> R {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
