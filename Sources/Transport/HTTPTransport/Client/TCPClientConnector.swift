//
//  TCPClientConnector.swift
//  HTTPTransport
//
//  The outbound half of the POSIX backbones: resolves a host (getaddrinfo, off the cooperative pool),
//  opens a non-blocking TCP socket per candidate address, completes the RFC 9293 three-way handshake
//  on the shared readiness loop (kqueue on Darwin, epoll on Linux), and hands the connected
//  descriptor to the same ``TransportConnection`` the server path uses — so client and server share
//  one audited send/receive core.
//
//  Cancellation of the connecting task closes the in-flight descriptor through the loop, which
//  resumes the parked writability waiter; callers bound connect latency by cancelling (timeouts).
//
//  Standards: getaddrinfo()/socket()/connect()/getsockopt(SO_ERROR) per POSIX.1-2017; TCP (RFC 9293)
//  over IPv4 (RFC 791) / IPv6 (RFC 4291).
//

internal import Dispatch
internal import Synchronization

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// Opens outbound TCP connections on the shared client readiness loops.
public enum TCPClientConnector {
    #if canImport(Darwin)
        typealias Loop = KqueueEventLoop
    #else
        typealias Loop = EpollEventLoop
    #endif

    /// One resolved candidate address (family + socket address bytes).
    struct Candidate: Sendable {
        let family: Int32
        let socketType: Int32
        let proto: Int32
        let address: [UInt8]
    }

    private static let loops: [Loop]? = {
        let count = max(1, min(4, Int(sysconf(Int32(_SC_NPROCESSORS_ONLN))) / 2))
        var created: [Loop] = []
        for _ in 0 ..< count {
            guard let loop = try? Loop() else {
                return created.isEmpty ? nil : created
            }
            loop.start()
            created.append(loop)
        }
        return created
    }()
    private static let nextLoop = Atomic<Int>(0)
    private static let nextID = Atomic<UInt64>(1 << 62)
    private static let resolverQueue = DispatchQueue(
        label: "http.transport.client.resolver",
        attributes: .concurrent
    )

    /// Connects to `host:port`, trying each resolved address in order until one succeeds.
    ///
    /// - Throws: ``TransportError/bindFailed(_:)`` when resolution fails, ``TransportError/ioFailed(_:)``
    ///   when every candidate refuses, and `CancellationError` when the task is cancelled.
    public static func connect(host: String, port: UInt16) async throws -> any TransportConnection {
        guard let loops, !loops.isEmpty else {
            throw TransportError.ioFailed("no client event loop available")
        }
        let candidates = try await resolve(host: host, port: port)
        var lastError = "no address for \(host)"
        for candidate in candidates {
            try Task.checkCancellation()
            let index = nextLoop.wrappingAdd(1, ordering: .relaxed).oldValue
            let loop = loops[index % loops.count]
            do {
                let fd = try await open(candidate, on: loop)
                let id = TransportConnectionID(nextID.wrappingAdd(1, ordering: .relaxed).oldValue)
                let peer = TransportAddress(host: host, port: port)
                #if canImport(Darwin)
                    return POSIXKqueueConnection(
                        id: id,
                        descriptor: fd,
                        peer: peer,
                        eventLoop: loop
                    )
                #else
                    return POSIXEpollConnection(id: id, descriptor: fd, peer: peer, eventLoop: loop)
                #endif
            }
            catch let error as CancellationError {
                throw error
            }
            catch {
                lastError = "\(error)"
            }
        }
        throw TransportError.ioFailed("connect \(host):\(port) failed: \(lastError)")
    }

    /// Resolves `host` with `getaddrinfo` on a dedicated queue (it blocks; never on the cooperative pool).
    static func resolve(host: String, port: UInt16) async throws -> [Candidate] {
        try await withCheckedThrowingContinuation { continuation in
            resolverQueue.async {
                continuation.resume(with: resolveBlocking(host: host, port: port))
            }
        }
    }

    private static func resolveBlocking(
        host: String, port: UInt16
    ) -> Result<[Candidate], any Error> {
        var hints = unsafe addrinfo()
        unsafe hints.ai_family = AF_UNSPEC
        #if canImport(Darwin)
            unsafe hints.ai_socktype = SOCK_STREAM
        #else
            unsafe hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #endif
        var resolved: UnsafeMutablePointer<addrinfo>?
        let status = unsafe getaddrinfo(host, String(port), &hints, &resolved)
        guard status == 0, let first = unsafe resolved else {
            return .failure(TransportError.bindFailed("getaddrinfo(\(host)) failed (\(status))"))
        }
        defer { unsafe freeaddrinfo(resolved) }
        var candidates: [Candidate] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = unsafe first
        while let node = unsafe cursor {
            let length = Int(unsafe node.pointee.ai_addrlen)
            if let address = unsafe node.pointee.ai_addr, length > 0 {
                let bytes = unsafe [UInt8](UnsafeRawBufferPointer(start: address, count: length))
                candidates.append(
                    Candidate(
                        family: unsafe node.pointee.ai_family,
                        socketType: unsafe node.pointee.ai_socktype,
                        proto: unsafe node.pointee.ai_protocol,
                        address: bytes
                    )
                )
            }
            unsafe cursor = node.pointee.ai_next
        }
        return .success(candidates)
    }

    /// Opens a non-blocking socket for `candidate` and completes its connect on `loop`.
    private static func open(_ candidate: Candidate, on loop: Loop) async throws -> Int32 {
        let fd = socket(candidate.family, candidate.socketType, candidate.proto)
        guard fd >= 0 else {
            throw TransportError.ioFailed("socket() errno \(errno)")
        }
        POSIXSocket.setNoSIGPIPE(fd)
        POSIXSocket.setNonBlocking(fd)
        POSIXSocket.setNoDelay(fd)
        let started = candidate.address.withUnsafeBytes { raw -> Int32 in
            guard let base = raw.baseAddress else {
                return -1
            }
            return unsafe systemConnect(fd, base, socklen_t(raw.count))
        }
        if started == 0 {
            return fd
        }
        guard errno == EINPROGRESS || errno == EINTR else {
            let captured = errno
            close(fd)
            throw TransportError.ioFailed("connect() errno \(captured)")
        }
        try await waitConnected(fd, on: loop)
        return fd
    }

    /// Parks until `fd` is writable (the connect settled), then reads its `SO_ERROR`.
    private static func waitConnected(_ fd: Int32, on loop: Loop) async throws {
        let closed = Atomic<Bool>(false)
        try await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                if !loop.waitWritable(fd, { continuation.resume() }) {
                    continuation.resume()
                }
            }
            if closed.load(ordering: .acquiring) {
                throw CancellationError()
            }
        } onCancel: {
            if !closed.exchange(true, ordering: .acquiringAndReleasing) {
                loop.closeDescriptor(fd)
            }
        }
        var socketError: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        let read = unsafe getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &length)
        guard read == 0, socketError == 0 else {
            if !closed.exchange(true, ordering: .acquiringAndReleasing) {
                loop.closeDescriptor(fd)
            }
            throw TransportError.ioFailed("connect() failed (SO_ERROR \(socketError))")
        }
    }

    /// `connect(2)`, named so the call does not resolve to ``connect(host:port:)``.
    private static func systemConnect(
        _ fd: Int32, _ address: UnsafeRawPointer, _ length: socklen_t
    ) -> Int32 {
        #if canImport(Darwin)
            unsafe Darwin.connect(fd, address.assumingMemoryBound(to: sockaddr.self), length)
        #else
            unsafe Glibc.connect(fd, address.assumingMemoryBound(to: sockaddr.self), length)
        #endif
    }
}
