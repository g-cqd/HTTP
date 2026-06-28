//
//  POSIXEpollTransport.swift
//  HTTPTransport
//
//  The Linux mirror of ``POSIXKqueueTransport`` (audit R4) — BSD sockets with hand-rolled `epoll(7)`
//  event loops. It shards across N loops (one dedicated thread each): one non-blocking listening socket
//  is accepted on the first loop, and each accepted connection is assigned **round-robin** to one of the
//  N loops, then accepted, read, served, and written **entirely on that loop's thread** (its serve task
//  is pinned to the loop, a `TaskExecutor`). That keeps median latency at the blocking backbone's level
//  while the bounded thread count keeps the tail tight.
//
//  Gated `#if canImport(Glibc)` (compiles to nothing off Linux); see ``EpollEventLoop``. The pre-R4 loop
//  was verified on Linux; the R4 rewrite needs a Linux CI pass (the macOS suite exercises the kqueue twin).
//
//  Standards: socket()/bind()/listen()/accept() per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP (RFC 9293)
//  over IPv4 (RFC 791) / IPv6 (RFC 4291). Readiness via Linux epoll(7).
//

#if canImport(Glibc)

    internal import Dispatch
    internal import Glibc
    internal import Synchronization

    /// The BSD-sockets + hand-rolled `epoll(7)` transport backbone (Linux), sharded across N event loops.
    ///
    /// Mutable state lives in a `Mutex` and the connection counters in `Atomic`s, so the type is
    /// `Sendable`. Accept runs on the first loop; each connection's I/O runs on its assigned loop (R4).
    public final class POSIXEpollTransport: ServerTransport {
        /// The backbone this transport implements.
        public let backbone: TransportBackbone = .posixEpoll

        private let configuration: TransportConfiguration
        private let state = Mutex<State>(State())
        private let connectionIDs = ConnectionIDAllocator()
        /// Round-robin cursor distributing accepted connections across the loops.
        private let nextLoop = Atomic<Int>(0)
        /// A side queue used only to re-arm accept after fd exhaustion, so the backoff delay never runs on
        /// an event loop (which also drives every connection's I/O) — audit F-EMFILE.
        private let backoffQueue = DispatchQueue(label: "http.transport.epoll.accept-backoff")

        private struct State {
            /// One loop per shard; each is a dedicated thread serving its assigned connections.
            var loops: [EpollEventLoop] = []
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

        /// Binds one non-blocking listening socket, spins up N event loops, and begins accepting on the
        /// first loop (assigning each connection round-robin to a loop).
        public func start() async throws -> AsyncStream<any TransportConnection> {
            let loopCount = max(1, configuration.eventLoopCount ?? Self.defaultLoopCount())
            let listener = try POSIXSocket.makeListenSocket(
                host: configuration.host,
                port: configuration.port,
                nonBlocking: true,
                reusePort: configuration.reusePort,
                backlog: configuration.backlog
            )
            var loops: [EpollEventLoop] = []
            loops.reserveCapacity(loopCount)
            for _ in 0 ..< loopCount {
                let loop = try EpollEventLoop()
                loop.start()
                loops.append(loop)
            }
            let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()
            state.withLock {
                $0.loops = loops
                $0.listenFD = listener.descriptor
                $0.boundPort = listener.port
                $0.isRunning = true
                $0.continuation = continuation
            }
            continuation.onTermination = { [weak self] _ in
                Task { await self?.shutdown() }
            }
            armAccept(
                listenFD: listener.descriptor,
                acceptLoop: loops[0],
                loops: loops,
                continuation: continuation
            )
            return stream
        }

        /// Closes the listening socket and stops every event loop.
        public func shutdown() async {
            let (loops, listenFD, continuation) = state.withLock {
                let loops = $0.loops
                let fd = $0.listenFD
                let cont = $0.continuation
                $0.loops = []
                $0.listenFD = -1
                $0.continuation = nil
                $0.isRunning = false
                return (loops, fd, cont)
            }
            // Finish the connection stream so a consumer's `for await` completes instead of hanging.
            continuation?.finish()
            if listenFD >= 0, let acceptLoop = loops.first {
                // close the listener on the loop that watches it
                acceptLoop.closeDescriptor(listenFD)
            }
            for loop in loops {
                loop.stop()
            }
        }

        // MARK: - Internals

        /// Auto-sizes the loop count to the online processor count (capped) — one loop per core, the
        /// nginx-style default.
        ///
        /// Override via ``TransportConfiguration/eventLoopCount``.
        private static func defaultLoopCount() -> Int {
            let online = sysconf(Int32(_SC_NPROCESSORS_ONLN))
            return online > 0 ? min(Int(online), 16) : 1
        }

        /// Arms one-shot read interest on the listening socket (re-armed after each accept batch).
        private func armAccept(
            listenFD: Int32,
            acceptLoop: EpollEventLoop,
            loops: [EpollEventLoop],
            continuation: AsyncStream<any TransportConnection>.Continuation
        ) {
            acceptLoop.waitReadable(listenFD) { [weak self] in
                self?
                    .acceptPending(
                        listenFD: listenFD,
                        acceptLoop: acceptLoop,
                        loops: loops,
                        continuation: continuation
                    )
            }
        }

        private func acceptPending(
            listenFD: Int32,
            acceptLoop: EpollEventLoop,
            loops: [EpollEventLoop],
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
                                listenFD: listenFD,
                                acceptLoop: acceptLoop,
                                loops: loops,
                                continuation: continuation
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
                // Round-robin the connection onto a loop; its I/O and serve task live there for its lifetime.
                let serveLoop = loops[
                    nextLoop.wrappingAdd(1, ordering: .relaxed).oldValue % loops.count]
                continuation.yield(
                    POSIXEpollConnection(
                        id: id,
                        descriptor: clientFD,
                        peer: POSIXSocket.peerAddress(from: address),
                        eventLoop: serveLoop
                    )
                )
            }
            armAccept(
                listenFD: listenFD, acceptLoop: acceptLoop, loops: loops, continuation: continuation
            )
        }

        /// Re-arms accept after the fd-exhaustion backoff, scheduled on ``backoffQueue`` so the wait never
        /// occupies an event loop.
        private func scheduleAcceptBackoff(
            listenFD: Int32,
            acceptLoop: EpollEventLoop,
            loops: [EpollEventLoop],
            continuation: AsyncStream<any TransportConnection>.Continuation
        ) {
            let delay = DispatchTimeInterval.milliseconds(POSIXSocket.acceptBackoffMilliseconds)
            backoffQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self, state.withLock(\.isRunning) else {
                    return
                }
                armAccept(
                    listenFD: listenFD,
                    acceptLoop: acceptLoop,
                    loops: loops,
                    continuation: continuation
                )
            }
        }
    }

#endif
