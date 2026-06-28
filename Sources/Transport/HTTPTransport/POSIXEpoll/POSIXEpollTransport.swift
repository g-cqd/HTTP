//
//  POSIXEpollTransport.swift
//  HTTPTransport
//
//  The Linux mirror of ``POSIXKqueueTransport`` — BSD sockets with a hand-rolled `epoll(7)` readiness
//  loop. A non-blocking listening socket is registered with the loop for read readiness; each readiness
//  event drains pending connections with accept() and re-arms, and every connection's I/O is driven by
//  the same loop. Reuses the shared (now portable) ``POSIXSocket`` plumbing.
//
//  Verified on Linux (Swift 6.5-dev, Ubuntu noble, aarch64) via apple/container — gated
//  `#if canImport(Glibc)`; see ``EpollEventLoop``. With this backbone the library builds and
//  `httpd-example` serves real HTTP/1.1 end to end on Linux: the G0 I/O floor is delivered.
//
//  Standards: socket()/bind()/listen()/accept() per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP (RFC 9293)
//  over IPv4 (RFC 791) / IPv6 (RFC 4291). Readiness via Linux epoll(7).
//

#if canImport(Glibc)

    internal import Dispatch
    internal import Glibc
    internal import Synchronization

    /// The BSD-sockets + hand-rolled `epoll(7)` transport backbone (Linux) — mirror of ``POSIXKqueueTransport``.
    ///
    /// Mutable state lives in a `Mutex` and the connection counter in an `Atomic`, so the type is
    /// `Sendable`. Accept and per-connection readiness both run on the shared ``EpollEventLoop``.
    public final class POSIXEpollTransport: ServerTransport {
        /// The backbone this transport implements.
        public let backbone: TransportBackbone = .posixEpoll

        private let configuration: TransportConfiguration
        private let state = Mutex<State>(State())
        private let connectionIDs = ConnectionIDAllocator()
        /// A side queue used only to re-arm accept after fd exhaustion, so the backoff delay never runs
        /// on the shared ``EpollEventLoop`` (which also drives every connection's I/O) — audit F-EMFILE.
        private let backoffQueue = DispatchQueue(label: "http.transport.epoll.accept-backoff")

        private struct State {
            var eventLoop: EpollEventLoop?
            var listenFD: Int32 = -1
            var boundPort: UInt16 = 0
            var isRunning = false
            /// The connection-stream continuation, finished on ``shutdown()`` so a consumer's `for await`
            /// completes instead of hanging.
            var continuation: AsyncStream<any TransportConnection>.Continuation?
        }

        /// Creates an epoll transport for `configuration`.
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

        /// Binds a non-blocking TCP socket and begins accepting via the epoll loop.
        public func start() async throws -> AsyncStream<any TransportConnection> {
            let listener = try POSIXSocket.makeListenSocket(
                host: configuration.host,
                port: configuration.port,
                nonBlocking: true,
                reusePort: configuration.reusePort,
                backlog: configuration.backlog
            )
            let listenFD = listener.descriptor
            let eventLoop = EpollEventLoop()
            eventLoop.start()
            let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()
            state.withLock {
                $0.eventLoop = eventLoop
                $0.listenFD = listenFD
                $0.boundPort = listener.port
                $0.isRunning = true
                $0.continuation = continuation
            }
            continuation.onTermination = { [weak self] _ in
                Task { await self?.shutdown() }
            }
            armAccept(listenFD: listenFD, eventLoop: eventLoop, continuation: continuation)
            return stream
        }

        /// Closes the listening socket and stops the event loop.
        public func shutdown() async {
            let (eventLoop, listenFD, continuation) = state.withLock {
                let loop = $0.eventLoop
                let fd = $0.listenFD
                let cont = $0.continuation
                $0.eventLoop = nil
                $0.listenFD = -1
                $0.continuation = nil
                $0.isRunning = false
                return (loop, fd, cont)
            }
            // Finish the connection stream so a consumer's `for await` completes instead of hanging.
            continuation?.finish()
            if listenFD >= 0 {
                eventLoop?.closeDescriptor(listenFD)
            }
            eventLoop?.stop()
        }

        // MARK: - Internals

        /// Arms one-shot read interest on the listening socket (re-armed after each accept batch).
        private func armAccept(
            listenFD: Int32,
            eventLoop: EpollEventLoop,
            continuation: AsyncStream<any TransportConnection>.Continuation
        ) {
            eventLoop.waitReadable(listenFD) { [weak self] in
                self?
                    .acceptPending(
                        listenFD: listenFD,
                        eventLoop: eventLoop,
                        continuation: continuation
                    )
            }
        }

        private func acceptPending(
            listenFD: Int32,
            eventLoop: EpollEventLoop,
            continuation: AsyncStream<any TransportConnection>.Continuation
        ) {
            guard state.withLock(\.isRunning) else {
                return
            }
            drain: while true {
                var address = sockaddr_storage()
                var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
                let clientFD = withUnsafeMutablePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        accept(listenFD, $0, &length)
                    }
                }
                if clientFD < 0 {
                    switch POSIXSocket.classifyAcceptError(errno) {
                        case .retry:
                            continue
                        case .backoff:
                            // fd exhaustion: re-arm after a brief delay on the side queue and return now,
                            // leaving the event loop free to service live connections (audit F-EMFILE).
                            scheduleAcceptBackoff(
                                listenFD: listenFD, eventLoop: eventLoop, continuation: continuation
                            )
                            return
                        case .wouldBlock, .stop:
                            break drain  // drained, or the listener was closed
                    }
                }
                POSIXSocket.setNonBlocking(clientFD)
                // No-op on Linux; the connection suppresses SIGPIPE via send(MSG_NOSIGNAL).
                POSIXSocket.setNoSIGPIPE(clientFD)
                // Disable Nagle — flush small responses now (the p99.9 tail).
                POSIXSocket.setNoDelay(clientFD)
                let id = connectionIDs.next()
                continuation.yield(
                    POSIXEpollConnection(
                        id: id,
                        descriptor: clientFD,
                        peer: POSIXSocket.peerAddress(from: address),
                        eventLoop: eventLoop
                    )
                )
            }
            armAccept(listenFD: listenFD, eventLoop: eventLoop, continuation: continuation)
        }

        /// Re-arms accept after the fd-exhaustion backoff, scheduled on ``backoffQueue`` so the wait never
        /// occupies the event loop. ``EpollEventLoop/waitReadable(_:_:)`` is safe to call off-loop (its
        /// registry is mutex-guarded and `epoll_ctl` is thread-safe), so the next readiness still fires
        /// ``acceptPending(listenFD:eventLoop:continuation:)`` back on the loop.
        private func scheduleAcceptBackoff(
            listenFD: Int32,
            eventLoop: EpollEventLoop,
            continuation: AsyncStream<any TransportConnection>.Continuation
        ) {
            let delay = DispatchTimeInterval.milliseconds(POSIXSocket.acceptBackoffMilliseconds)
            backoffQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self, state.withLock(\.isRunning) else {
                    return
                }
                armAccept(listenFD: listenFD, eventLoop: eventLoop, continuation: continuation)
            }
        }
    }

#endif
