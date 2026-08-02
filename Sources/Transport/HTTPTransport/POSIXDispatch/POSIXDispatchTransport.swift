//
//  POSIXDispatchTransport.swift
//  HTTPTransport
//
//  Backbone 3 — BSD sockets with GCD readiness. A non-blocking listening socket is watched by a
//  DispatchSource read source; each readiness event drains all pending connections with accept(),
//  and each connection is driven by a DispatchIO channel (kqueue under the hood, no hand-rolled
//  event loop).
//
//  Standards: socket()/bind()/listen()/accept() per POSIX.1-2017 (IEEE Std 1003.1-2017); the
//  listener is a TCP (RFC 9293) stream socket over IPv4 (RFC 791).
//

internal import Darwin
internal import Dispatch
internal import Synchronization

/// The BSD-sockets + GCD `DispatchSource`/`DispatchIO` transport backbone.
///
/// Mutable state lives in a `Mutex` and the connection counter in an `Atomic`, so the type is
/// `Sendable`. Accept readiness runs on `acceptQueue`; connection I/O runs on the shared `ioQueue`.
public final class POSIXDispatchTransport: ServerTransport {
    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .posixDispatch

    private let configuration: TransportConfiguration
    private let acceptQueue = DispatchQueue(
        label: "http.transport.posix-dispatch.accept",
        qos: .userInitiated
    )
    // `.userInitiated` so readiness worker threads are scheduled promptly under CPU contention — at
    // default QoS the pool's threads get descheduled behind unrelated work (a p99/p99.9 jitter source).
    private let ioQueue = DispatchQueue(
        label: "http.transport.posix-dispatch.io",
        qos: .userInitiated,
        attributes: .concurrent
    )
    private let state = Mutex<State>(State())
    private let connectionIDs = ConnectionIDAllocator()
    /// Whether the read source is currently suspended for admission saturation.
    ///
    /// `DispatchSource` **traps** on an unbalanced `resume()`, so suspend/resume must be strictly 1:1;
    /// this flag is the balance, and *every* transition runs on ``acceptQueue`` so they are serialized
    /// against each other and against the accept handler that suspends (audit F8).
    ///
    /// "Every" is load-bearing and was not always true: ``shutdown()`` issues the balancing `resume()`
    /// too, and it used to do so on whatever thread awaited it. The three helpers below assert their
    /// queue with `dispatchPrecondition`, so the discipline is enforced rather than described — the
    /// previous version of this comment claimed serialization that one caller did not honour, and the
    /// result was an intermittent SIGTRAP (audit FLAKE-1).
    private let isSuspendedForAdmission = Mutex<Bool>(false)

    private struct State {
        var acceptSource: (any DispatchSourceRead)?
        /// The listening descriptor, closed by the source's cancel handler — kept here so
        /// ``shutdown()`` can re-point that handler at its own continuation.
        var listenFD: Int32 = -1
        var boundPort: UInt16 = 0
        /// The endpoint `getsockname(2)` reports for the listener.
        var boundEndpoint: BindEndpoint?
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

    /// Creates a Dispatch transport for `configuration`.
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

    /// The local endpoint actually bound (meaningful after ``start()`` returns), or `nil` before binding.
    ///
    /// Read back from the kernel with `getsockname(2)` at bind time, not derived from the configuration:
    /// `port` `0` means "whichever the OS chose" and `host` may have been a name or a wildcard, so the
    /// realized answer is the only one an operator log or an `Alt-Svc` advertisement (RFC 7838) can use.
    public var boundEndpoint: BindEndpoint? {
        state.withLock(\.boundEndpoint)
    }

    /// Binds a non-blocking TCP socket and begins accepting via a read source.
    public func start(
        admission: ConnectionAdmission?
    ) async throws -> AsyncStream<any TransportConnection> {
        let listener = try POSIXSocket.makeListenSocket(
            host: configuration.host,
            port: configuration.port,
            nonBlocking: true,
            reusePort: configuration.reusePort,
            backlog: configuration.backlog
        )
        let (stream, continuation) = AsyncStream<any TransportConnection>.makeStream()

        let source = DispatchSource.makeReadSource(
            fileDescriptor: listener.descriptor,
            queue: acceptQueue
        )
        source.setEventHandler { [weak self] in
            self?.acceptPending(listenFD: listener.descriptor, continuation: continuation)
        }
        source.setCancelHandler {
            close(listener.descriptor)
        }
        state.withLock {
            $0.acceptSource = source
            $0.listenFD = listener.descriptor
            $0.boundPort = listener.port
            $0.boundEndpoint = POSIXSocket.readBoundEndpoint(of: listener.descriptor)
            $0.closeLatch = ListenerCloseLatch()
            $0.isRunning = true
            $0.continuation = continuation
            $0.gate = AcceptGate(admission: admission)
        }
        continuation.onTermination = { [weak self] _ in
            Task { await self?.shutdown() }
        }
        // Resume the read source once the gate's live count falls back to its hysteresis watermark.
        // Hopped onto `acceptQueue` so it is serialized *after* the accept handler that suspended —
        // an out-of-order resume would leave the flag unbalanced and the listener suspended forever.
        admission?
            .onResume { [weak self] in
                // Bound strongly first — see the note on the Network.framework transport's resume.
                guard let self else {
                    return
                }
                acceptQueue.async { [self] in resumeAcceptAfterAdmission() }
            }
        source.resume()
        return stream
    }

    /// Cancels the read source and waits for its cancel handler to close the listening descriptor.
    ///
    /// Waiting is the contract, not a nicety: POSIX.1-2017 keeps the local address bound to a listening
    /// socket until it is closed, so returning early leaves an immediate rebind of the same port racing
    /// the close and failing `bind(2)` with `EADDRINUSE`. `DispatchSource.cancel()` only *schedules* the
    /// cancel handler on the source's queue, so the previous version — which resumed as soon as
    /// `balanceAndCancel` returned — resolved one queue hop before `close(2)` ran. That is a narrower
    /// window than the kqueue/epoll backbones' (a hop on one queue versus a cross-thread loop wakeup),
    /// which is why the shared matrix only ever caught it there; it is the same defect.
    ///
    /// The cancel handler installed at ``start(admission:)`` is *replaced* here so the resume happens
    /// inside it, after `close(2)`. Replacing it is safe because every transition on this source runs on
    /// ``acceptQueue`` and the state swap below makes this the only caller that ever reaches a live
    /// source — the start-time handler stays in place as the fallback for a cancel this method never
    /// issues. If the source is currently suspended for the fd-exhaustion backoff, delivery waits out
    /// that backoff's balancing `resume()`; bounded, and still strictly better than not waiting.
    ///
    /// Idempotent, and safe against a concurrent second call: the state swap is the arbiter, so exactly
    /// one caller sees a live source and every other finds `nil` — which matters because
    /// ``start(admission:)`` also wires `continuation.onTermination` to shut down.
    public func shutdown() async {
        // `closeLatch` is deliberately NOT cleared — see ``POSIXKqueueTransport/shutdown()``.
        let (source, listenFD, continuation, latch) = state.withLock {
            let current = $0.acceptSource
            let fd = $0.listenFD
            let cont = $0.continuation
            $0.acceptSource = nil
            $0.listenFD = -1
            $0.continuation = nil
            $0.isRunning = false
            return (current, fd, cont, $0.closeLatch)
        }
        // Finish the connection stream so a consumer's `for await` completes instead of hanging.
        continuation?.finish()
        guard let latch else {
            return  // never started
        }
        guard let source else {
            // Another caller took the source and is cancelling it; wait for THEIR close, do not race
            // ahead of it. This is the case the Linux job found (bind-contract `rebind after stop`).
            await latch.wait()
            return
        }
        // Balance and cancel ON `acceptQueue`, which is what makes the 1:1 discipline hold.
        //
        // This used to run wherever `shutdown()` was awaited. The flag and the source live under two
        // *different* mutexes and the `suspend()`/`resume()` calls happen outside both, so an accept
        // handler that had set the flag and not yet suspended could be overtaken here: this side read
        // "suspended", issued the balancing `resume()` against a source that was still running — an
        // unbalanced resume, which traps — and then cancelled, leaving the handler to suspend a source
        // about to be released, which traps in `_dispatch_queue_xref_dispose`.
        //
        // Observed as an intermittent SIGTRAP in `AcceptBackpressureTests` under `--parallel` (audit
        // FLAKE-1), roughly once in six full-suite runs, and unreproducible in isolation. The three
        // transitions already ran here and the comments already claimed serialization; only shutdown
        // did not honour it. `suspend()` stops the *source*, never the queue, so this block still runs.
        acceptQueue.async { [self] in
            source.setCancelHandler {
                close(listenFD)
                latch.signal()
            }
            balanceAndCancel(source)
        }
        await latch.wait()
    }

    /// Balances any outstanding admission suspend and cancels `source`.
    ///
    /// Extracted so the queue requirement is *checked* rather than commented. Moving this call back
    /// off ``acceptQueue`` — the shape that produced the SIGTRAP — trips the precondition on the very
    /// first shutdown, deterministically, instead of resurfacing as a one-in-six crash somewhere else.
    private func balanceAndCancel(_ source: any DispatchSourceRead) {
        dispatchPrecondition(condition: .onQueue(acceptQueue))
        // A suspended source never delivers its cancel handler, and deallocating one traps.
        if isSuspendedForAdmission.withLock({ suspended -> Bool in
            defer { suspended = false }
            return suspended
        }) {
            source.resume()
        }
        source.cancel()
    }

    // MARK: - Internals

    /// Drains every pending connection on a readiness event (a non-blocking socket is level- but
    /// drained edge-style to avoid repeated wakeups), charging each against the admission gate BEFORE
    /// it is yielded.
    ///
    /// The connection stream stays `.unbounded` deliberately. `AsyncStream`'s buffering policy *drops*
    /// on overflow, and a dropped connection here is a leaked file descriptor — an unbounded-loss bug
    /// strictly worse than the queue depth it would bound. The bound comes from admission instead:
    /// because a slot is charged before `yield`, the stream's depth can never exceed the gate's total.
    /// Do not "fix" this by adding a dropping policy.
    private func acceptPending(
        listenFD: Int32,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        let gate = state.withLock(\.gate)
        // A refused connection is closed here, on the accept queue: it has no readiness source yet, so
        // a direct `close(2)` cannot race one.
        let closeRefused: (Int32) -> Void = { close($0) }
        drain: while state.withLock(\.isRunning) {
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
                        // fd exhaustion: suspend accept readiness and resume after a brief delay, so the
                        // accept queue neither busy-retries nor blocks on a sleep (audit F-EMFILE).
                        suspendAcceptForBackoff()
                        return
                    case .wouldBlock, .stop:
                        break drain  // drained, or the listener was closed
                }
            }
            let peer = POSIXSocket.peerAddress(from: address)
            switch gate.admit(descriptor: clientFD, host: peer.host, close: closeRefused) {
                case .rejectedContinue:
                    continue  // this peer is over ITS cap; others are not — keep draining
                case .saturatedStop:
                    // This backbone has a real readiness source, so the backpressure is an explicit
                    // suspend; the gate resumes it at the hysteresis watermark.
                    suspendAcceptForAdmission()
                    return
                case .admit(let ticket, let saturated):
                    yieldConnection(
                        clientFD,
                        peer: peer,
                        ticket: ticket,
                        continuation: continuation
                    )
                    if saturated {
                        suspendAcceptForAdmission()  // that was the last slot
                        return
                    }
            }
        }
    }

    /// Configures an admitted descriptor, gives it a serial queue, and yields it carrying its slot.
    private func yieldConnection(
        _ clientFD: Int32,
        peer: TransportAddress,
        ticket: AdmissionTicket?,
        continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        POSIXSocket.setNonBlocking(clientFD)
        POSIXSocket.setNoSIGPIPE(clientFD)  // audit T-F1: a peer RST mid-write must not kill us
        POSIXSocket.setNoDelay(clientFD)  // disable Nagle — flush small responses now (p99.9)
        // A per-connection *serial* queue targeting the shared concurrent pool: it serializes this
        // connection's read/write readiness handling and close (so a close never races a syscall on
        // the fd), while still spreading connections across the pool's threads.
        let connectionQueue = DispatchQueue(
            label: "http.transport.posix-dispatch.conn",
            qos: .userInitiated,
            target: ioQueue
        )
        continuation.yield(
            POSIXDispatchConnection(
                id: connectionIDs.next(),
                descriptor: clientFD,
                peer: peer,
                queue: connectionQueue,
                admissionTicket: ticket
            )
        )
    }

    /// Suspends accept readiness because the admission gate is saturated (audit F8).
    ///
    /// Balanced 1:1 with ``resumeAcceptAfterAdmission()`` by ``isSuspendedForAdmission`` — an
    /// unbalanced `resume()` traps. Both run on ``acceptQueue``: this one from inside the accept
    /// handler, the resume as a block enqueued behind it, so the pair can never invert.
    private func suspendAcceptForAdmission() {
        dispatchPrecondition(condition: .onQueue(acceptQueue))
        let shouldSuspend = isSuspendedForAdmission.withLock { suspended -> Bool in
            guard !suspended else {
                return false
            }
            suspended = true
            return true
        }
        guard shouldSuspend, let source = state.withLock(\.acceptSource) else {
            return
        }
        source.suspend()
    }

    /// Resumes accept readiness once the gate's live count falls back to its hysteresis watermark.
    private func resumeAcceptAfterAdmission() {
        dispatchPrecondition(condition: .onQueue(acceptQueue))
        let shouldResume = isSuspendedForAdmission.withLock { suspended -> Bool in
            guard suspended else {
                return false
            }
            suspended = false
            return true
        }
        guard shouldResume, let source = state.withLock(\.acceptSource) else {
            return
        }
        source.resume()
    }

    /// Suspends the accept read source and resumes it after the fd-exhaustion backoff (audit F-EMFILE).
    ///
    /// `suspend()` and the deferred `resume()` are balanced 1:1: the resume captures the source
    /// strongly and always runs, so a suspended source is never deallocated (which would trap), and
    /// resuming a source that ``shutdown()`` has since cancelled is harmless. While suspended the
    /// source delivers no readiness, so the accept queue idles instead of busy-retrying `EMFILE`.
    private func suspendAcceptForBackoff() {
        dispatchPrecondition(condition: .onQueue(acceptQueue))
        guard let source = state.withLock(\.acceptSource) else {
            return
        }
        source.suspend()
        let delay = DispatchTimeInterval.milliseconds(POSIXSocket.acceptBackoffMilliseconds)
        acceptQueue.asyncAfter(deadline: .now() + delay) {
            source.resume()
        }
    }
}
