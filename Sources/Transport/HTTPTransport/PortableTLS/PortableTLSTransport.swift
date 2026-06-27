//
//  PortableTLSTransport.swift
//  HTTPTransport
//
//  The portable (non-Network.framework) TLS server backbone — ADR 0004. Binds a POSIX listening
//  socket via the shared `POSIXSocket` helper (the same plumbing the swift-system/kqueue/dispatch
//  backbones use), accepts connections on a dedicated blocking-`accept()` thread, wraps each accepted
//  descriptor in a libssl session (`SSL_new` + `SSL_set_fd`), drives the TLS handshake off the accept
//  thread, and surfaces the connection only once the handshake settles — the TLS analog of the Network
//  backbone yielding at `.ready`. A failed handshake (e.g. ALPN no-overlap, ALPACA-refused) is never
//  surfaced. The single shared `SSL_CTX` is built once from the `TransportTLS` identity.
//
//  Selected by ``TransportFactory`` for ``TransportBackbone/portableTLS``; gated
//  `#if canImport(CHTTPBoringSSL)` (the opt-in `HTTP_PORTABLE_TLS` build).
//
//  Standards: TCP (RFC 9293) over IPv4 (RFC 791) / IPv6 (RFC 4291) via POSIX.1-2017 sockets, carrying
//  TLS 1.3 (RFC 8446); ALPN (RFC 7301).
//

#if canImport(CHTTPBoringSSL)

    internal import CHTTPBoringSSL
    internal import Darwin
    internal import Dispatch
    internal import Synchronization

    /// The portable libssl-over-POSIX-socket TLS backbone (`HTTP_PORTABLE_TLS`).
    ///
    /// State lives in a `Mutex`; the blocking `accept()` runs on `acceptQueue`, and each accepted
    /// connection's handshake + I/O run on the connection's own serial queue, so the accept thread never
    /// blocks on a handshake. The shared `SSL_CTX` is owned by the accept loop and freed when it exits
    /// (after which no `SSL_new` can race it; live `SSL`s retain their own reference).
    public final class PortableTLSTransport: ServerTransport {
        /// The backbone this transport implements.
        public let backbone: TransportBackbone = .portableTLS

        private let configuration: TransportConfiguration
        private let acceptQueue = DispatchQueue(label: "http.transport.portable-tls.accept")
        private let state = Mutex<State>(State())
        private let connectionIDs = ConnectionIDAllocator()

        private struct State {
            /// The shared server `SSL_CTX`, swappable by ``reload(tls:)``: new handshakes use the
            /// current one, while in-flight `SSL`s keep the context they handshook with.
            var context: ContextBox?
            var listenDescriptor: Int32?
            var boundPort: UInt16 = 0
            var isRunning = false
        }

        /// Carries the non-`Sendable` `SSL_CTX` pointer across the accept-thread hop.
        ///
        /// Sound because the `SSL_CTX` is read-only after `start()` and freed only by the single accept
        /// loop that holds it.
        private struct ContextBox: @unchecked Sendable {
            let pointer: OpaquePointer
        }

        /// Creates a portable TLS transport for `configuration` (which must carry a TLS identity).
        public init(configuration: TransportConfiguration) {
            self.configuration = configuration
        }

        deinit {
            // No teardown beyond ARC; ``shutdown()`` closes the listener and the accept loop frees the
            // `SSL_CTX`.
        }

        /// The actual bound port (meaningful after ``start()`` returns).
        public var boundPort: UInt16 {
            state.withLock(\.boundPort)
        }

        /// Builds the shared `SSL_CTX`, binds the listening socket, and begins accepting.
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
                SSL_CTX_free(sslContext)
                throw error
            }
            let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()
            state.withLock {
                $0.context = ContextBox(pointer: sslContext)
                $0.listenDescriptor = listener.descriptor
                $0.boundPort = listener.port
                $0.isRunning = true
            }
            continuation.onTermination = { [weak self] _ in
                Task { await self?.shutdown() }
            }
            acceptQueue.async { [weak self] in
                self?
                    .acceptLoop(
                        listenDescriptor: listener.descriptor,
                        continuation: continuation
                    )
            }
            return stream
        }

        /// Closes the listening socket, which unblocks and ends the accept loop (which then frees the
        /// `SSL_CTX`).
        public func shutdown() async {
            let descriptor: Int32? = state.withLock {
                let current = $0.listenDescriptor
                $0.listenDescriptor = nil
                $0.isRunning = false
                return current
            }
            if let descriptor {
                _ = Darwin.close(descriptor)
            }
        }

        /// Hot-reloads the TLS identity (G4b): swaps the shared `SSL_CTX` so new handshakes use `tls`,
        /// while connections already accepted keep serving on the context they handshook with.
        ///
        /// A `Mutex`-guarded pointer swap — no port rebind (the listening socket is untouched), unlike
        /// the Network backbone's restart-based reload, so there is no accept gap. A bad identity throws
        /// before the running context is touched. The old context is released after the swap; in-flight
        /// `SSL`s retain it (refcounted), so it is freed only once the last such connection closes.
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
                SSL_CTX_free(newContext)  // not accepting: nothing to swap into
                throw TransportError.closed
            }
            if let previous = outcome.previous {
                SSL_CTX_free(previous.pointer)
            }
        }

        // MARK: - Internals

        private func acceptLoop(
            listenDescriptor: Int32,
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
                surface(clientFD: clientFD, address: address, continuation: continuation)
            }
            continuation.finish()
            let context = state.withLock { state -> ContextBox? in
                let current = state.context
                state.context = nil
                return current
            }
            if let context {
                SSL_CTX_free(context.pointer)
            }
        }

        /// Wraps an accepted descriptor in a libssl session and surfaces it once its handshake settles.
        private func surface(
            clientFD: Int32,
            address: sockaddr_storage,
            continuation: AsyncStream<any TransportConnection>.Continuation
        ) {
            // Snapshot the current context under the lock and hold a reference across `SSL_new`, so a
            // concurrent ``reload(tls:)`` that swaps and frees it cannot pull it out from under us; the
            // new `SSL` then retains the context it handshakes with.
            guard let context = state.withLock(\.context) else {
                _ = Darwin.close(clientFD)
                return
            }
            _ = SSL_CTX_up_ref(context.pointer)
            let ssl = SSL_new(context.pointer)
            SSL_CTX_free(context.pointer)
            guard let ssl else {
                _ = Darwin.close(clientFD)
                return
            }
            SSL_set_fd(ssl, clientFD)
            let connection = PortableTLSConnection(
                id: connectionIDs.next(),
                peer: POSIXSocket.peerAddress(from: address),
                ssl: ssl,
                descriptor: clientFD,
                clientAuth: configuration.tls?.clientAuth ?? .none,
                verifyPeer: configuration.tls?.verifyPeer
            )
            // Drive the handshake off the accept thread; surface only on success — a failed handshake
            // (e.g. ALPN no-overlap / ALPACA refusal) is torn down, never yielded.
            Task {
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

#endif
