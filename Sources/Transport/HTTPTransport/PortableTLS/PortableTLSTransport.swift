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

    /// Poisons a listening descriptor with `shutdown(2)` `SHUT_RDWR`, ahead of its `close(2)`.
    ///
    /// This is the Linux half of releasing a blocking-`accept(2)` listener, and it must come FIRST.
    /// POSIX.1-2017 does not specify what `close(2)` does to a thread blocked in `accept(2)` on the
    /// same descriptor, and the two kernels answer differently (measured, 2026-08): Darwin releases
    /// the bound port inside `close(2)` and wakes the blocked accept (`ECONNABORTED`); Linux does
    /// neither — the socket stays bound through the accept's file reference until a connection
    /// arrives, which after a shutdown is never. `shutdown(2)` on the listening socket is what Linux
    /// answers with: it releases the port immediately (before the woken thread has left the syscall)
    /// and wakes the accept with `EINVAL`. On Darwin the call fails `ENOTCONN` — a listening socket
    /// is not connected — but still wakes an already-blocked accept, and the `close(2)` that follows
    /// does the rest, so the pair is correct on both platforms in every interleaving.
    private func poisonFD(_ descriptor: Int32) {
        #if canImport(Darwin)
            _ = Darwin.shutdown(descriptor, SHUT_RDWR)
        #else
            // Glibc surfaces `SHUT_RDWR` as `Int` — the same import divergence `POSIXSocket`
            // normalizes for `SOCK_STREAM`.
            _ = Glibc.shutdown(descriptor, Int32(SHUT_RDWR))
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
        /// Parks the blocking accept thread while the admission gate is saturated (audit F8).
        ///
        /// This backbone accepts on a dedicated thread with a *blocking* `accept(2)`, so it has no
        /// readiness registration to leave un-armed and no `DispatchSource` to suspend; parking the
        /// thread is the equivalent backpressure. A `DispatchSemaphore` counts, so a resume that
        /// arrives before the park is banked rather than lost.
        private let admissionResume = DispatchSemaphore(value: 0)

        private struct State {
            /// The shared server `SSL_CTX`, swappable by ``reload(tls:)``.
            var context: ContextBox?
            /// One loop per shard; each is a dedicated thread serving its assigned TLS connections.
            var loops: [TLSEventLoop] = []
            var listenDescriptor: Int32?
            var boundPort: UInt16 = 0
            /// The endpoint `getsockname(2)` reports for the listener, `nil` before binding.
            var boundEndpoint: BindEndpoint?
            /// Signalled once the listening descriptor is genuinely closed and its port released.
            ///
            /// Awaited by EVERY ``shutdown()`` caller, not just the one that performs the close —
            /// see ``ListenerCloseLatch``.
            var closeLatch: ListenerCloseLatch?
            var isRunning = false
            /// The admission policy applied between `accept(2)` and `SSL_new` (audit F8), ungated
            /// until ``start(admission:)`` installs the server's gate.
            var gate = AcceptGate(admission: nil)
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

        /// The local endpoint actually bound (meaningful after ``start()`` returns), or `nil` before
        /// binding.
        ///
        /// Read back from the kernel with `getsockname(2)` at bind time, not derived from the
        /// configuration: `port` `0` means "whichever the OS chose" and `host` may have been a name or
        /// a wildcard, so the realized answer is the only one an operator log or an `Alt-Svc`
        /// advertisement (RFC 7838) can use. Same shape as the four POSIX backbones — this transport
        /// binds through the shared ``POSIXSocket`` helper, so the answer comes from the same call.
        public var boundEndpoint: BindEndpoint? {
            state.withLock(\.boundEndpoint)
        }

        /// Builds the shared `SSL_CTX`, spins up N event loops, binds the listening socket, and accepts.
        public func start(
            admission: ConnectionAdmission?
        ) async throws -> AsyncStream<any TransportConnection> {
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
                $0.boundEndpoint = POSIXSocket.readBoundEndpoint(of: listener.descriptor)
                $0.closeLatch = ListenerCloseLatch()
                $0.isRunning = true
                $0.gate = AcceptGate(admission: admission)
            }
            continuation.onTermination = { [weak self] _ in
                Task { await self?.shutdown() }
            }
            // Unpark the blocking accept thread once the gate's live count falls back to its
            // hysteresis watermark.
            admission?.onResume { [weak self] in self?.admissionResume.signal() }
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

        /// Closes the listening socket — not returning until its port is released — and stops the
        /// event loops.
        ///
        /// The woken accept thread ends the connection stream and frees the `SSL_CTX`.
        ///
        /// The close is `shutdown(2)`-then-`close(2)`, in that order, because this backbone accepts
        /// with a *blocking* `accept(2)` on a dedicated thread and the close-only version leaks the
        /// port on Linux: see ``poisonFD(_:)`` for the measured per-kernel semantics. By the time the
        /// pair has run, POSIX's `EADDRINUSE` window is over on both platforms — a caller that then
        /// rebinds the same port must succeed, which is the bind-contract `rebind after stop` row.
        ///
        /// Idempotent, and synchronous for EVERY caller, not just the one that performs the close.
        /// The state swap below is the arbiter — exactly one caller sees the live descriptor — and
        /// the losers of that race await the same ``ListenerCloseLatch`` the winner signals, because
        /// ``start(admission:)`` wires `continuation.onTermination` to shut down, so a consumer
        /// dropping the stream races an explicit `shutdown()` by construction; a loser that returned
        /// through the `nil` it found would resolve with the port possibly still held.
        public func shutdown() async {
            // `closeLatch` is deliberately NOT cleared: a caller that arrives after the close still
            // has to find it, and find it already signalled.
            let (descriptor, loops, latch) = state.withLock {
                let fd = $0.listenDescriptor
                let loops = $0.loops
                $0.listenDescriptor = nil
                $0.loops = []
                $0.isRunning = false
                return (fd, loops, $0.closeLatch)
            }
            if let descriptor {
                poisonFD(descriptor)  // wakes the blocked accept; releases the port on Linux
                closeFD(descriptor)  // releases the port on Darwin; drops the fd-table entry
            }
            // The accept thread may be parked on the admission gate; closing the listener alone would
            // not wake it, so signal too. (`isRunning` is already false, so it exits its park loop.)
            admissionResume.signal()
            if let latch {
                if descriptor != nil {
                    latch.signal()  // the performer: the poison + close above released the port
                }
                // Every caller waits here, including the ones that found the descriptor already
                // taken. A never-started transport has no latch, and nothing to wait for.
                await latch.wait()
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
            let gate = state.withLock(\.gate)
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
                // Charge BEFORE `surface(...)` — before `SSL_new` and before the handshake — so a peer
                // that completes the TCP connect and then never sends a ClientHello is still holding a
                // slot against the ceiling, which is precisely the Slowloris-shaped case the audit's
                // "queued and handshaking connections" wording is about.
                let peer = POSIXSocket.peerAddress(from: address)
                switch gate.admit(descriptor: clientFD, host: peer.host, close: closeFD) {
                    case .rejectedContinue:
                        continue  // this peer is over ITS cap; others are not — keep accepting
                    case .saturatedStop:
                        parkUntilAdmissionResumes(gate)
                        continue
                    case .admit(let ticket, let saturated):
                        // audit T-F1: a peer RST mid-write must not kill us; Nagle off for the tail.
                        POSIXSocket.setNoSIGPIPE(clientFD)
                        POSIXSocket.setNoDelay(clientFD)
                        surface(
                            clientFD,
                            peer: peer,
                            ticket: ticket,
                            loops: loops,
                            continuation: continuation
                        )
                        if saturated {
                            parkUntilAdmissionResumes(gate)
                        }
                }
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

        /// Parks the accept thread until the admission gate clears its saturation latch.
        ///
        /// The timed wait is a safety valve, not the wakeup path: the gate's resume signals the
        /// semaphore, and a signal that arrives before the park is banked (semaphores count). The
        /// timeout only bounds the park if the gate is torn down while we are in it.
        private func parkUntilAdmissionResumes(_ gate: AcceptGate) {
            guard let admission = gate.admission else {
                return
            }
            while state.withLock(\.isRunning), admission.isSaturated {
                _ = admissionResume.wait(timeout: .now() + .milliseconds(50))
            }
        }

        /// Wraps an admitted descriptor in a libssl session over memory BIOs, assigns it a loop,
        /// drives the handshake inline on that loop, and surfaces it once the handshake settles.
        ///
        /// The slot in `ticket` is already charged. If any step below fails the connection is torn
        /// down without being yielded, and the ticket's `deinit` returns the slot — the failure paths
        /// need no bookkeeping of their own.
        private func surface(
            _ clientFD: Int32,
            peer: TransportAddress,
            ticket: AdmissionTicket?,
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
                peer: peer,
                ssl: ssl,
                readBIO: readBIO,
                writeBIO: writeBIO,
                descriptor: clientFD,
                eventLoop: loop,
                clientAuth: configuration.tls?.clientAuth ?? .none,
                verifyPeer: configuration.tls?.verifyPeer,
                admissionTicket: ticket
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
