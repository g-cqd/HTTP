//
//  SwiftSystemTransport.swift
//  HTTPTransport
//
//  Backbone 2 — apple/swift-system typed descriptors over the POSIX socket syscalls, driven
//  **event-driven** by the shared ``KqueueEventLoop`` (audit R4). swift-system exposes FileDescriptor
//  (read/write/close) but not socket setup, so the listener is created via the shared `POSIXSocket`
//  helper and accepted (non-blocking) sockets are wrapped in FileDescriptor. It shards across N loops
//  (one dedicated thread each): one non-blocking listening socket is accepted on the first loop, and
//  each accepted connection is assigned round-robin to a loop, then served entirely on that loop's
//  thread (its serve task pinned to the loop). The swift-system-typed twin of ``POSIXKqueueTransport``:
//  it serves to show the FileDescriptor API is not inherently blocking — the prior thread-per-connection
//  blocking model was a deliberate reference, replaced here by the event-driven path (same p50/tail as
//  the kqueue backbone).
//
//  Standards: TCP (RFC 9293) over IPv4 (RFC 791) via POSIX.1-2017 (IEEE Std 1003.1-2017) sockets;
//  readiness via BSD kqueue.
//

internal import Darwin
internal import Dispatch
internal import Synchronization
internal import SystemPackage

/// The apple/swift-system transport backbone (typed FileDescriptor I/O), sharded across N kqueue loops.
///
/// Mutable state lives in a `Mutex` and the connection counters in `Atomic`s, so the type is
/// `Sendable`. Accept runs on the first loop; each connection's I/O runs on its assigned loop (R4).
public final class SwiftSystemTransport: ServerTransport {
    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .swiftSystem

    private let configuration: TransportConfiguration
    private let state = Mutex<State>(State())
    private let connectionIDs = ConnectionIDAllocator()
    /// Round-robin cursor distributing accepted connections across the loops.
    private let nextLoop = Atomic<Int>(0)
    /// A side queue used only to re-arm accept after fd exhaustion, so the backoff delay never runs on an
    /// event loop (which also drives every connection's I/O) — audit F-EMFILE.
    private let backoffQueue = DispatchQueue(label: "http.transport.swift-system.accept-backoff")

    private struct State {
        var loops: [KqueueEventLoop] = []
        var listenDescriptor: FileDescriptor?
        var listenFD: Int32 = -1
        var boundPort: UInt16 = 0
        /// Signalled once the listening descriptor is closed.
        ///
        /// Awaited by EVERY ``shutdown()`` caller, not just the one that performs the close —
        /// see ``ListenerCloseLatch``.
        var closeLatch: ListenerCloseLatch?
        var isRunning = false
        var continuation: AsyncStream<any TransportConnection>.Continuation?
        /// The admission policy applied between `accept(2)` and `yield` (audit F8), ungated until
        /// ``start(admission:)`` installs the server's gate.
        var gate = AcceptGate(admission: nil)
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

    /// Binds one non-blocking listening socket, spins up N event loops, and begins accepting on the
    /// first loop (assigning each connection round-robin to a loop).
    public func start(
        admission: ConnectionAdmission?
    ) async throws -> AsyncStream<any TransportConnection> {
        let loopCount = max(1, configuration.eventLoopCount ?? Self.defaultLoopCount())
        let listener = try POSIXSocket.makeListenSocket(
            host: configuration.host,
            port: configuration.port,
            nonBlocking: true,
            reusePort: configuration.reusePort,
            backlog: configuration.backlog
        )
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
            $0.listenDescriptor = FileDescriptor(rawValue: listener.descriptor)
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
        // Re-arm once the gate's live count falls back to its hysteresis watermark, on the side queue
        // so the `kevent` registration never occupies an event loop.
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
    /// Same contract, same reasoning and the same idempotence argument as
    /// ``POSIXKqueueTransport/shutdown()``: this backbone shares that one's ``KqueueEventLoop``, so it
    /// shared the defect too — `shutdown()` enqueued the listening descriptor's close and returned, and
    /// an immediate rebind of the same port raced it into `EADDRINUSE`. The wait is a continuation the
    /// loop thread resumes, so no cooperative-pool thread is blocked on it.
    public func shutdown() async {
        // `closeLatch` is deliberately NOT cleared — see ``POSIXKqueueTransport/shutdown()``.
        let (loops, listenFD, continuation, latch) = state.withLock {
            let loops = $0.loops
            let fd = $0.listenFD
            let cont = $0.continuation
            $0.loops = []
            $0.listenDescriptor = nil
            $0.listenFD = -1
            $0.continuation = nil
            $0.isRunning = false
            return (loops, fd, cont, $0.closeLatch)
        }
        continuation?.finish()
        guard let latch else {
            return  // never started
        }
        if listenFD >= 0 {
            if let acceptLoop = loops.first {
                acceptLoop.closeDescriptor(listenFD) { latch.signal() }
            }
            else {
                close(listenFD)
                latch.signal()
            }
        }
        await latch.wait()
        for loop in loops {
            loop.stop()
        }
    }

    // MARK: - Internals

    /// The loop that watches the listening socket, or `nil` once ``shutdown()`` has taken it.
    ///
    /// The shutdown-ordering test seam — see ``POSIXKqueueTransport/acceptLoop``.
    var acceptLoop: KqueueEventLoop? {
        state.withLock(\.loops.first)
    }

    /// Auto-sizes the loop count to the performance-core count (Apple Silicon P-cores) — see
    /// ``POSIXKqueueTransport``.
    ///
    /// Override via ``TransportConfiguration/eventLoopCount``.
    private static func defaultLoopCount() -> Int {
        var perfCores: Int32 = 0
        var size = MemoryLayout<Int32>.stride
        if sysctlbyname("hw.perflevel0.physicalcpu", &perfCores, &size, nil, 0) == 0, perfCores > 0
        {
            return Int(perfCores)
        }
        let online = sysconf(Int32(_SC_NPROCESSORS_ONLN))
        return online > 0 ? min(Int(online), 8) : 1
    }

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
                        scheduleAcceptBackoff(
                            listenFD: listenFD,
                            acceptLoop: acceptLoop,
                            loops: loops,
                            continuation: continuation
                        )
                        return
                    case .wouldBlock, .stop:
                        break drain
                }
            }
            let peer = POSIXSocket.peerAddress(from: address)
            switch gate.admit(descriptor: clientFD, host: peer.host, close: closeRefused) {
                case .rejectedContinue:
                    continue  // this peer is over ITS cap; others are not — keep draining
                case .saturatedStop:
                    // Return WITHOUT re-arming: the one-shot readiness registration makes "don't
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
        POSIXSocket.setNonBlocking(clientFD)  // event-driven I/O needs a non-blocking fd
        POSIXSocket.setNoSIGPIPE(clientFD)  // audit T-F1: a peer RST mid-write must not kill us
        POSIXSocket.setNoDelay(clientFD)  // disable Nagle — flush small responses now (p99.9)
        let serveLoop = loops[nextLoop.wrappingAdd(1, ordering: .relaxed).oldValue % loops.count]
        continuation.yield(
            SwiftSystemConnection(
                id: connectionIDs.next(),
                descriptor: FileDescriptor(rawValue: clientFD),
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
