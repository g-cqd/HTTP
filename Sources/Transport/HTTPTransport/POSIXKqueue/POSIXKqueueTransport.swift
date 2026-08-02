//
//  POSIXKqueueTransport.swift
//  HTTPTransport
//
//  Backbone 4 — BSD sockets with hand-rolled kqueue event loops (closest to the hardware). It shards
//  across N loops (one dedicated thread each, audit R4): one non-blocking listening socket is accepted
//  on the first loop, and each accepted connection is assigned **round-robin** to one of the N loops,
//  then accepted, read, served, and written **entirely on that loop's thread** (its serve task is
//  pinned to the loop, a `TaskExecutor`). That keeps median latency at the blocking backbone's level
//  while the bounded thread count keeps the tail tight. (Round-robin rather than SO_REUSEPORT because
//  Darwin's SO_REUSEPORT does not load-balance accepts across sockets the way Linux does.)
//
//  Standards: socket()/bind()/listen()/accept() per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP
//  (RFC 9293) over IPv4 (RFC 791). Readiness via BSD kqueue.
//

internal import Darwin
internal import Dispatch
internal import Synchronization

/// The BSD-sockets + hand-rolled kqueue transport backbone, sharded across N event loops.
///
/// Mutable state lives in a `Mutex` and the connection counters in `Atomic`s, so the type is
/// `Sendable`. Accept runs on the first loop; each connection's I/O runs on its assigned loop (R4).
/// Also carries the ``TransportBackbone/unixDomainSocket`` listener mode on Darwin: only the
/// listener's address family differs (`AF_UNIX` at ``TransportConfiguration/unixSocketPath``), the
/// accepted-connection machinery is identical.
public final class POSIXKqueueTransport: ServerTransport {
    /// The backbone this transport implements — ``TransportBackbone/posixKqueue``, or
    /// ``TransportBackbone/unixDomainSocket`` when configured with a socket path.
    public var backbone: TransportBackbone { configuration.backbone }

    private let configuration: TransportConfiguration
    private let state = Mutex<State>(State())
    private let connectionIDs = ConnectionIDAllocator()
    /// Round-robin cursor distributing accepted connections across the loops.
    private let nextLoop = Atomic<Int>(0)
    /// A side queue used only to re-arm accept after fd exhaustion, so the backoff delay never runs on an
    /// event loop (which also drives every connection's I/O) — audit F-EMFILE.
    private let backoffQueue = DispatchQueue(label: "http.transport.kqueue.accept-backoff")

    private struct State {
        /// One loop per shard; each is a dedicated thread serving its assigned connections.
        var loops: [KqueueEventLoop] = []
        var listenFD: Int32 = -1
        var boundPort: UInt16 = 0
        /// Signalled once the listening descriptor is closed.
        ///
        /// Awaited by EVERY ``shutdown()`` caller, not just the one that performs the close —
        /// see ``ListenerCloseLatch``.
        var closeLatch: ListenerCloseLatch?
        var isRunning = false
        /// The connection-stream continuation, finished on ``shutdown()`` so a consumer's `for await`
        /// completes instead of hanging.
        var continuation: AsyncStream<any TransportConnection>.Continuation?
        /// The admission policy applied between `accept(2)` and `yield` (audit F8), ungated until
        /// ``start(admission:)`` installs the server's gate.
        var gate = AcceptGate(admission: nil)
    }

    /// Creates a kqueue transport for `configuration`.
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

    /// Binds one non-blocking listening socket — TCP, or `AF_UNIX` for the
    /// ``TransportBackbone/unixDomainSocket`` mode — spins up N event loops, and begins accepting on
    /// the first loop (assigning each connection round-robin to a loop).
    public func start(
        admission: ConnectionAdmission?
    ) async throws -> AsyncStream<any TransportConnection> {
        let loopCount = max(1, configuration.eventLoopCount ?? Self.defaultLoopCount())
        let listener: (descriptor: Int32, port: UInt16)
        if configuration.backbone == .unixDomainSocket {
            guard let path = configuration.unixSocketPath else {
                throw TransportError.bindFailed(
                    "the .unixDomainSocket backbone requires TransportConfiguration.unixSocketPath"
                )
            }
            listener = (
                try POSIXSocket.makeUnixListenSocket(path: path, backlog: configuration.backlog),
                0  // a UNIX-domain listener has no port
            )
        }
        else {
            listener = try POSIXSocket.makeListenSocket(
                host: configuration.host,
                port: configuration.port,
                nonBlocking: true,
                reusePort: configuration.reusePort,
                backlog: configuration.backlog
            )
        }
        var loops: [KqueueEventLoop] = []
        loops.reserveCapacity(loopCount)
        for _ in 0 ..< loopCount {
            let loop = try KqueueEventLoop()
            loop.start()
            loops.append(loop)
        }
        let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()
        state.withLock {
            $0.loops = loops
            $0.listenFD = listener.descriptor
            $0.boundPort = listener.port
            $0.closeLatch = ListenerCloseLatch()
            $0.isRunning = true
            $0.continuation = continuation
            $0.gate = AcceptGate(admission: admission)
        }
        continuation.onTermination = { [weak self] _ in
            Task { await self?.shutdown() }
        }
        // An immutable snapshot: `loops` is a var (built incrementally above) and the resume closure
        // runs concurrently on the side queue, so capturing the var there is a data-race smell.
        let acceptLoops = loops
        // Re-arm once the gate's live count falls back to its hysteresis watermark. Dispatched on the
        // side queue so the `kevent` registration never runs on an event loop (which also drives every
        // live connection's I/O), and so it is serialized after the accept batch that suspended us.
        admission?
            .onResume { [weak self] in
                self?
                    .scheduleAcceptRearm(
                        listenFD: listener.descriptor,
                        acceptLoop: acceptLoops[0],
                        loops: acceptLoops,
                        continuation: continuation
                    )
            }
        // Accept on the first loop; `acceptPending` fans connections out across all loops.
        armAccept(
            listenFD: listener.descriptor,
            acceptLoop: loops[0],
            loops: loops,
            continuation: continuation
        )
        return stream
    }

    /// Closes the listening socket — **waiting for the close to land** — and stops every event loop.
    ///
    /// Returning before the listening descriptor is actually closed is a restart-under-load hazard:
    /// POSIX.1-2017 keeps the local address bound to a listening socket until it is closed, so a server
    /// that stops and immediately rebinds the same port gets `EADDRINUSE` (errno 48 on Darwin, 98 on
    /// Linux) and fails to come back. This used to end in a bare `acceptLoop.closeDescriptor(listenFD)`,
    /// which only *enqueues* the close onto the loop thread — `shutdown()` then resolved with the port
    /// still held, and the bind-contract matrix's `rebind after stop` row carried it as a known issue.
    ///
    /// The wait is a continuation resumed **by the loop thread**, not a blocking wait: parking a
    /// cooperative-pool thread on a semaphore until an event loop got around to a close would trade this
    /// race for a pool-starvation one, and on the single-loop configuration the loop's own pinned tasks
    /// run on that pool. Suspending instead leaves the thread free and lets the loop drive the close —
    /// the same shape ``POSIXDispatchTransport/shutdown()`` uses to reach its accept queue.
    ///
    /// Idempotent, and safe against a concurrent second call: the state swap below is the arbiter, so
    /// exactly one caller ever sees a live `listenFD` and a non-empty `loops`, and every other caller
    /// finds `-1`/`[]` and returns without enqueuing anything. That matters because
    /// ``start(admission:)`` also wires `continuation.onTermination` to shut down, so a consumer
    /// dropping the stream races an explicit `shutdown()` by construction.
    public func shutdown() async {
        // `closeLatch` is deliberately NOT cleared: a caller that arrives after the close still has to
        // find it, and find it already signalled.
        let (loops, listenFD, continuation, latch) = state.withLock {
            let loops = $0.loops
            let fd = $0.listenFD
            let cont = $0.continuation
            $0.loops = []
            $0.listenFD = -1
            $0.continuation = nil
            $0.isRunning = false
            return (loops, fd, cont, $0.closeLatch)
        }
        // Finish the connection stream so a consumer's `for await` completes instead of hanging.
        continuation?.finish()
        guard let latch else {
            return  // never started: there is no listener to close and nothing to wait for
        }
        if listenFD >= 0 {
            // Close the listener on the loop that watches it. The loop is still running here — `stop()`
            // is below — and even if it were not, its teardown drain runs the whole inbox
            // unconditionally before the thread exits, so the latch cannot be left unsignalled.
            if let acceptLoop = loops.first {
                acceptLoop.closeDescriptor(listenFD) { latch.signal() }
            }
            else {
                close(listenFD)  // no loop watches it; nothing to serialize against
                latch.signal()
            }
        }
        // Every caller waits here, including the ones that found the descriptor already taken.
        await latch.wait()
        for loop in loops {
            loop.stop()
        }
    }

    // MARK: - Internals

    /// The loop that watches the listening socket, or `nil` once ``shutdown()`` has taken it.
    ///
    /// A seam for the shutdown-ordering test: parking this loop is the only way to observe, from
    /// outside, that ``shutdown()`` is *suspended* on its close rather than merely quick. See
    /// ``KqueueEventLoop/queuedControlWork``.
    var acceptLoop: KqueueEventLoop? {
        state.withLock(\.loops.first)
    }

    /// Auto-sizes the loop count to the **performance-core** count — one loop per P-core.
    ///
    /// Running loops on E-cores (or oversubscribing P-cores) adds scheduling tail latency, so this is
    /// the sweet spot between median (more loops → less per-loop queueing) and tail (fewer threads →
    /// less contention); a colocated load test may want it lower still. Override via
    /// ``TransportConfiguration/eventLoopCount``.
    private static func defaultLoopCount() -> Int {
        var perfCores: Int32 = 0
        var size = MemoryLayout<Int32>.stride
        if sysctlbyname("hw.perflevel0.physicalcpu", &perfCores, &size, nil, 0) == 0, perfCores > 0
        {
            return Int(perfCores)  // Apple Silicon P-core count
        }
        let online = sysconf(Int32(_SC_NPROCESSORS_ONLN))  // Intel / non-heterogeneous fallback
        return online > 0 ? min(Int(online), 8) : 1
    }

    /// Arms one-shot read interest on the listening socket (re-armed after each accept batch).
    private func armAccept(
        listenFD: Int32,
        acceptLoop: KqueueEventLoop,
        loops: [KqueueEventLoop],
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

    /// Drains every pending connection, charging each against the admission gate BEFORE it is yielded.
    ///
    /// The connection stream stays `.unbounded` deliberately. `AsyncStream`'s buffering policy *drops*
    /// on overflow, and a dropped connection here is a leaked file descriptor — an unbounded-loss bug
    /// strictly worse than the queue depth it would bound. The bound comes from admission instead:
    /// because a slot is charged before `yield`, the stream's depth can never exceed the gate's total.
    /// Do not "fix" this by adding a dropping policy.
    private func acceptPending(
        listenFD: Int32,
        acceptLoop: KqueueEventLoop,
        loops: [KqueueEventLoop],
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        let (running, gate) = state.withLock { ($0.isRunning, $0.gate) }
        guard running else {
            return
        }
        // A refused connection is closed here, on the accept loop: it was never registered with any
        // kqueue, so a direct `close(2)` cannot race a readiness handler.
        let closeRefused: (Int32) -> Void = { close($0) }
        // The fairness quantum (PERF-1). Draining until EAGAIN let an accept storm hold this loop in
        // `accept(2)` for as long as the backlog lasted, while the connections it had ALREADY accepted
        // waited behind it. Breaking out re-arms the listener, so nothing is dropped — an un-drained
        // backlog leaves it immediately readable — but live sockets get their readiness turn first.
        var batch = 0
        drain: while batch < ReactorQuantum.acceptBatch {
            batch += 1
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
            // A UNIX-domain peer carries no host:port — report the socket path (one shared "host",
            // which is also the right key for the per-client connection cap: local peers are one class).
            let peer =
                configuration.unixSocketPath.map { TransportAddress(host: $0, port: 0) }
                ?? POSIXSocket.peerAddress(from: address)
            switch gate.admit(descriptor: clientFD, host: peer.host, close: closeRefused) {
                case .rejectedContinue:
                    continue  // this peer is over ITS cap; others are not — keep draining
                case .saturatedStop:
                    // Return WITHOUT re-arming: the `EV_ADD|EV_ONESHOT` registration makes "don't
                    // re-arm" the backpressure. The kernel fills the listen(2) backlog and finally
                    // refuses SYNs; the gate re-arms us at its hysteresis watermark.
                    return
                case .admit(let ticket, let saturated):
                    yieldConnection(
                        clientFD,
                        peer: peer,
                        ticket: ticket,
                        loops: loops,
                        continuation: continuation
                    )
                    if saturated {
                        return  // that was the last slot — same backpressure, no re-arm
                    }
            }
        }
        armAccept(
            listenFD: listenFD, acceptLoop: acceptLoop, loops: loops, continuation: continuation
        )
    }

    /// Configures an admitted descriptor, assigns it a loop, and yields it carrying its slot.
    private func yieldConnection(
        _ clientFD: Int32,
        peer: TransportAddress,
        ticket: AdmissionTicket?,
        loops: [KqueueEventLoop],
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        POSIXSocket.setNonBlocking(clientFD)
        POSIXSocket.setNoSIGPIPE(clientFD)  // audit T-F1: a peer RST mid-write must not kill us
        POSIXSocket.setNoDelay(clientFD)  // disable Nagle — flush small responses now (p99.9)
        // Round-robin the connection onto a loop; its I/O and serve task live there for its lifetime.
        let serveLoop = loops[nextLoop.wrappingAdd(1, ordering: .relaxed).oldValue % loops.count]
        continuation.yield(
            POSIXKqueueConnection(
                id: connectionIDs.next(),
                descriptor: clientFD,
                peer: peer,
                eventLoop: serveLoop,
                admissionTicket: ticket
            )
        )
    }

    /// Re-arms accept from the gate's hysteresis resume, on ``backoffQueue`` so the `kevent`
    /// registration never occupies an event loop.
    private func scheduleAcceptRearm(
        listenFD: Int32,
        acceptLoop: KqueueEventLoop,
        loops: [KqueueEventLoop],
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        backoffQueue.async { [weak self] in
            guard let self, state.withLock(\.isRunning) else {
                return
            }
            armAccept(
                listenFD: listenFD, acceptLoop: acceptLoop, loops: loops, continuation: continuation
            )
        }
    }

    /// Re-arms accept after the fd-exhaustion backoff, scheduled on ``backoffQueue`` so the wait never
    /// occupies an event loop.
    private func scheduleAcceptBackoff(
        listenFD: Int32,
        acceptLoop: KqueueEventLoop,
        loops: [KqueueEventLoop],
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        let delay = DispatchTimeInterval.milliseconds(POSIXSocket.acceptBackoffMilliseconds)
        backoffQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self, state.withLock(\.isRunning) else {
                return
            }
            armAccept(
                listenFD: listenFD, acceptLoop: acceptLoop, loops: loops, continuation: continuation
            )
        }
    }
}
