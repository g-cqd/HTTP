//
//  PortableTLSTransport.swift
//  HTTPTransport
//
//  The portable (non-Network.framework) TLS server backbone — ADR 0004, now **event-driven** (audit
//  R4). Binds a POSIX listening socket via the shared `POSIXSocket` helper, accepts on a dedicated
//  blocking-`accept()` thread, then wraps each accepted (non-blocking) descriptor in a libssl session
//  driven through **memory BIOs** on one of N shared kqueue/epoll loops (round-robin) — the handshake
//  and all TLS I/O run inline on the loop thread, no thread-per-connection. The connection is surfaced
//  only once its handshake settles. The single shared `SSL_CTX` is built once from the `TransportTLS`
//  identity and hot-swappable via ``reload(tls:)``.
//
//  Selected by ``TransportFactory`` for ``TransportBackbone/portableTLS``; gated
//  `#if canImport(CHTTPBoringSSLShims)` (the opt-in `HTTP_PORTABLE_TLS` build).
//
//  Standards: TCP (RFC 9293) over IPv4 (RFC 791) / IPv6 (RFC 4291) via POSIX.1-2017 sockets, carrying
//  TLS 1.3 (RFC 8446); ALPN (RFC 7301).
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import Dispatch
    internal import Synchronization

    /// Closes a raw socket descriptor, qualified per platform (resolves from `Darwin` on Apple /
    /// `Glibc` on Linux, where the bare `close` import differs).
    private func closeFD(_ descriptor: Int32) {
        #if canImport(Darwin)
            _ = Darwin.close(descriptor)
        #else
            _ = Glibc.close(descriptor)
        #endif
    }

    /// The portable libssl-over-POSIX-socket TLS backbone (`HTTP_PORTABLE_TLS`), event-driven (audit R4).
    ///
    /// State lives in a `Mutex`; the blocking `accept()` runs on `acceptQueue`, each accepted connection
    /// is assigned round-robin to one of N ``TLSEventLoop``s, and its handshake + I/O run inline on that
    /// loop via memory BIOs. The shared `SSL_CTX` is owned by the accept loop and freed when it exits.
    public final class PortableTLSTransport: ServerTransport {
        /// The backbone this transport implements.
        public let backbone: TransportBackbone = .portableTLS

        private let configuration: TransportConfiguration
        private let acceptQueue = DispatchQueue(
            label: "http.transport.portable-tls.accept",
            qos: .userInitiated
        )
        private let state = Mutex<State>(State())
        private let connectionIDs = ConnectionIDAllocator()
        /// Round-robin cursor distributing accepted connections across the loops.
        private let nextLoop = Atomic<Int>(0)

        private struct State {
            /// The shared server `SSL_CTX`, swappable by ``reload(tls:)``.
            var context: ContextBox?
            /// One loop per shard; each is a dedicated thread serving its assigned TLS connections.
            var loops: [TLSEventLoop] = []
            var listenDescriptor: Int32?
            var boundPort: UInt16 = 0
            var isRunning = false
        }

        /// Carries the non-`Sendable` `SSL_CTX` pointer across the accept-thread hop.
        private struct ContextBox: @unchecked Sendable {
            let pointer: OpaquePointer
        }

        /// Creates a portable TLS transport for `configuration` (which must carry a TLS identity).
        public init(configuration: TransportConfiguration) {
            self.configuration = configuration
        }

        deinit {
            // No teardown beyond ARC; ``shutdown()`` closes the listener and stops the loops.
        }

        /// The actual bound port (meaningful after ``start()`` returns).
        public var boundPort: UInt16 {
            state.withLock(\.boundPort)
        }

        /// Builds the shared `SSL_CTX`, spins up N event loops, binds the listening socket, and accepts.
        public func start() async throws -> AsyncStream<any TransportConnection> {
            guard let tls = configuration.tls else {
                throw TransportError.tlsConfigurationFailed(
                    "the portable TLS backbone requires a TLS identity"
                )
            }
            let sslContext = try OpenSSLTLS.serverContext(tls)
            let listener: (descriptor: Int32, port: UInt16)
            do {
                listener = try POSIXSocket.makeListenSocket(
                    host: configuration.host,
                    port: configuration.port,
                    nonBlocking: false,
                    reusePort: configuration.reusePort,
                    backlog: configuration.backlog
                )
            }
            catch {
                CHTTPBoringSSL_SSL_CTX_free(sslContext)
                throw error
            }
            let loopCount = max(1, configuration.eventLoopCount ?? Self.defaultLoopCount())
            var loops: [TLSEventLoop] = []
            loops.reserveCapacity(loopCount)
            do {
                for _ in 0 ..< loopCount {
                    let loop = try TLSEventLoop()
                    loop.start()
                    loops.append(loop)
                }
            }
            catch {
                CHTTPBoringSSL_SSL_CTX_free(sslContext)
                closeFD(listener.descriptor)
                throw error
            }
            let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()
            state.withLock {
                $0.context = ContextBox(pointer: sslContext)
                $0.loops = loops
                $0.listenDescriptor = listener.descriptor
                $0.boundPort = listener.port
                $0.isRunning = true
            }
            continuation.onTermination = { [weak self] _ in
                Task { await self?.shutdown() }
            }
            // Capture an immutable snapshot: `loops` is a var (built incrementally above), and the accept
            // loop runs concurrently on `acceptQueue`, so referencing the var there is a data-race smell.
            let acceptLoops = loops
            acceptQueue.async { [weak self] in
                self?
                    .acceptLoop(
                        listenDescriptor: listener.descriptor,
                        loops: acceptLoops,
                        continuation: continuation
                    )
            }
            return stream
        }

        /// Closes the listening socket (ending the accept loop, which frees the `SSL_CTX`) and stops the
        /// event loops.
        public func shutdown() async {
            let (descriptor, loops): (Int32?, [TLSEventLoop]) = state.withLock {
                let fd = $0.listenDescriptor
                let loops = $0.loops
                $0.listenDescriptor = nil
                $0.loops = []
                $0.isRunning = false
                return (fd, loops)
            }
            if let descriptor {
                closeFD(descriptor)
            }
            for loop in loops {
                loop.stop()
            }
        }

        /// Hot-reloads the TLS identity (G4b): swaps the shared `SSL_CTX` so new handshakes use `tls`,
        /// while connections already accepted keep serving on the context they handshook with.
        public func reload(tls: TransportTLS) async throws {
            let newContext = try OpenSSLTLS.serverContext(tls)
            let outcome: (running: Bool, previous: ContextBox?) = state.withLock { state in
                guard state.isRunning else {
                    return (false, nil)
                }
                let previous = state.context
                state.context = ContextBox(pointer: newContext)
                return (true, previous)
            }
            guard outcome.running else {
                CHTTPBoringSSL_SSL_CTX_free(newContext)
                throw TransportError.closed
            }
            if let previous = outcome.previous {
                CHTTPBoringSSL_SSL_CTX_free(previous.pointer)
            }
        }

        // MARK: - Internals

        /// Auto-sizes the loop count to the performance-core count (see ``POSIXKqueueTransport``).
        private static func defaultLoopCount() -> Int {
            #if canImport(Darwin)
                var perfCores: Int32 = 0
                var size = MemoryLayout<Int32>.stride
                if sysctlbyname("hw.perflevel0.physicalcpu", &perfCores, &size, nil, 0) == 0,
                    perfCores > 0
                {
                    return Int(perfCores)
                }
            #endif
            let online = sysconf(Int32(_SC_NPROCESSORS_ONLN))
            return online > 0 ? min(Int(online), 8) : 1
        }

        private func acceptLoop(
            listenDescriptor: Int32,
            loops: [TLSEventLoop],
            continuation: AsyncStream<any TransportConnection>.Continuation
        ) {
            drain: while state.withLock(\.isRunning) {
                var address = sockaddr_storage()
                var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
                let clientFD = withUnsafeMutablePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        accept(listenDescriptor, $0, &length)
                    }
                }
                if clientFD < 0 {
                    switch POSIXSocket.classifyAcceptError(errno) {
                        case .retry:
                            continue
                        case .backoff:
                            usleep(useconds_t(POSIXSocket.acceptBackoffMilliseconds * 1_000))
                            continue
                        case .wouldBlock, .stop:
                            break drain
                    }
                }
                // audit T-F1: a peer RST mid-write must not kill us; disable Nagle for p99.9 tail.
                POSIXSocket.setNoSIGPIPE(clientFD)
                POSIXSocket.setNoDelay(clientFD)
                surface(clientFD, address: address, loops: loops, continuation: continuation)
            }
            continuation.finish()
            let context = state.withLock { state -> ContextBox? in
                let current = state.context
                state.context = nil
                return current
            }
            if let context {
                CHTTPBoringSSL_SSL_CTX_free(context.pointer)
            }
        }

        /// Wraps an accepted descriptor in a libssl session over memory BIOs, assigns it a loop, drives
        /// the handshake inline on that loop, and surfaces it once the handshake settles.
        private func surface(
            _ clientFD: Int32,
            address: sockaddr_storage,
            loops: [TLSEventLoop],
            continuation: AsyncStream<any TransportConnection>.Continuation
        ) {
            // Hold a reference across `SSL_new` so a concurrent ``reload(tls:)`` cannot free the context
            // under us; the new `SSL` then retains the context it handshakes with.
            guard let context = state.withLock(\.context) else {
                closeFD(clientFD)
                return
            }
            _ = CHTTPBoringSSL_SSL_CTX_up_ref(context.pointer)
            let ssl = CHTTPBoringSSL_SSL_new(context.pointer)
            CHTTPBoringSSL_SSL_CTX_free(context.pointer)
            guard let ssl else {
                closeFD(clientFD)
                return
            }
            // Memory BIOs: SSL reads ciphertext from `readBIO`, writes ciphertext to `writeBIO`; the
            // connection pumps both to/from the non-blocking socket. `SSL_set_bio` transfers ownership
            // (both are freed by `SSL_free`).
            guard let readBIO = CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()),
                let writeBIO = CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem())
            else {
                CHTTPBoringSSL_SSL_free(ssl)
                closeFD(clientFD)
                return
            }
            CHTTPBoringSSL_SSL_set_bio(ssl, readBIO, writeBIO)
            POSIXSocket.setNonBlocking(clientFD)  // event-driven pump needs a non-blocking fd
            let loop = loops[nextLoop.wrappingAdd(1, ordering: .relaxed).oldValue % loops.count]
            let connection = PortableTLSConnection(
                id: connectionIDs.next(),
                peer: POSIXSocket.peerAddress(from: address),
                ssl: ssl,
                readBIO: readBIO,
                writeBIO: writeBIO,
                descriptor: clientFD,
                eventLoop: loop,
                clientAuth: configuration.tls?.clientAuth ?? .none,
                verifyPeer: configuration.tls?.verifyPeer
            )
            // Drive the handshake inline on the connection's loop; surface only on success — a failed
            // handshake (ALPN no-overlap / ALPACA refusal) is torn down, never yielded.
            Task {
                await withTaskExecutorPreference(loop) {
                    do {
                        try await connection.performHandshake()
                    }
                    catch {
                        await connection.close()
                        return
                    }
                    continuation.yield(connection)
                }
            }
        }
    }

#endif
