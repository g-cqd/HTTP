//
//  KqueueEventLoop.swift
//  HTTPTransport
//
//  A hand-rolled kqueue event loop that is ALSO a `TaskExecutor` (audit R4 — tail-latency variance /
//  p50 parity). One dedicated thread runs a real run loop that interleaves I/O readiness and task
//  execution: each turn it `kevent`-waits for socket readiness, runs the ready read/write handlers,
//  then drains the executor's task queue — all on the same thread. Pinning a connection's serve task
//  to this loop (via `withTaskExecutorPreference`) therefore runs read → parse → route → respond →
//  write **inline on the loop thread**, with no hop to the global cooperative pool. That hop is what
//  cost the event-driven backbones their median vs the blocking swiftSystem backbone (which the kernel
//  wakes directly on its read thread); removing it is how kqueue reaches swiftSystem's p50 while
//  keeping a bounded thread count (so the p99/p99.9 tail stays tight). N loops (one per core) shard the
//  work — see ``KqueueEventLoopGroup``.
//
//  Cross-thread wakeups use an `EVFILT_USER` user event: enqueuing a job (or a close/stop) from another
//  thread triggers it so the blocked `kevent` returns at once instead of waiting out the idle timeout.
//
//  Standards: kqueue()/kevent()/EVFILT_USER are the BSD/Darwin readiness primitives (Darwin manuals,
//  not POSIX); the descriptors they watch are POSIX.1-2017 TCP (RFC 9293) sockets.
//

internal import Darwin
internal import Dispatch
internal import Synchronization

/// A readiness multiplexer over `kqueue`/`kevent` that doubles as a `TaskExecutor` so work pinned to it
/// runs inline on the loop thread (audit R4).
final class KqueueEventLoop: Sendable, TaskExecutor {
    /// Disambiguates the Darwin `kevent` *struct* from the `kevent()` *function* (same C name).
    private typealias KEvent = kevent

    private let kq: Int32
    /// Owns the single loop thread: ``start()`` submits one block that runs ``runLoop()`` for the loop's
    /// lifetime. `.userInitiated` so the thread is scheduled promptly under CPU contention (a default-QoS
    /// loop thread gets descheduled behind unrelated work — a p99/p99.9 jitter source).
    private let thread = DispatchQueue(label: "http.transport.kqueue.loop", qos: .userInitiated)
    private let registry = Mutex<Registry>(Registry())
    /// Work submitted from off-loop (executor jobs + control closures), drained each turn on the loop
    /// thread.
    ///
    /// Separate from `registry` so enqueuing never contends with readiness bookkeeping.
    private let inbox = Mutex<Inbox>(Inbox())
    /// Control closures queued but not yet run — the lock-free mirror behind ``queuedControlWork``.
    private let controlBacklog = Atomic<Int>(0)

    /// The `EVFILT_USER` identity used purely as a cross-thread wakeup (never a real fd).
    private static let wakeIdent = UInt(0xFFFF_FFF0)

    private struct Registry {
        /// Every waiter parked on a descriptor, per direction — a *list*, not one slot.
        ///
        /// A single slot meant the second waiter on a descriptor silently overwrote the first, whose
        /// continuation was then resumed by nothing: not by readiness, which had forgotten it, and not
        /// by ``closeDescriptor(_:)``, which also took only one. Waking all of them is sound because
        /// readiness is level information — each waiter retries its syscall and re-parks on `EAGAIN`.
        ///
        /// Identified rather than anonymous so a refused registration unwinds *its own* waiter; the
        /// closures are not comparable, and removing "the last one" would race a concurrent park.
        var readHandlers: [Int32: [Waiter]] = [:]
        var writeHandlers: [Int32: [Waiter]] = [:]
        var nextWaiterID: UInt64 = 0
        var isRunning = true

        /// Registers `handler` for `fd` in `direction`, returning its removal id.
        mutating func park(
            _ handler: @escaping @Sendable () -> Void,
            fd: Int32,
            direction: WritableKeyPath<Self, [Int32: [Waiter]]>
        ) -> UInt64 {
            nextWaiterID += 1
            let id = nextWaiterID
            self[keyPath: direction][fd, default: []].append(Waiter(id: id, handler: handler))
            return id
        }

        /// Removes the waiter `id` parked on `fd`, if it is still there.
        mutating func unpark(
            id: UInt64,
            fd: Int32,
            direction: WritableKeyPath<Self, [Int32: [Waiter]]>
        ) {
            self[keyPath: direction][fd]?.removeAll { $0.id == id }
            if self[keyPath: direction][fd]?.isEmpty == true {
                self[keyPath: direction].removeValue(forKey: fd)
            }
        }
    }

    /// One parked readiness waiter, identified so it can be removed without comparing closures.
    private struct Waiter {
        let id: UInt64
        let handler: @Sendable () -> Void
    }

    private struct Inbox {
        /// Continuations of tasks pinned to this loop, run on the loop thread (the no-hop hot path).
        var jobs: [UnownedJob] = []
        /// Out-of-band control work (close/cancel) that must run on the loop thread, serialized against
        /// the readiness handlers so a close never races an in-flight read/write on the same fd.
        var control: [@Sendable () -> Void] = []
        /// True while the loop thread is running handlers/jobs — i.e. NOT parked in `kevent`.
        ///
        /// An off-loop caller wakes the loop only when this is `false`; an on-loop caller (the pinned
        /// serve task itself — the R4 no-hop hot path) skips the `kevent` wakeup syscall entirely,
        /// because the loop re-drains the inbox and re-checks the readiness set before it parks again
        /// (audit — per-request wakeup elimination). Guarded by the inbox `Mutex` so the block-decision
        /// (`onLoop = false` + `isEmpty`) and an off-loop enqueue serialize: no lost wakeup.
        var onLoop = false
        var isEmpty: Bool { jobs.isEmpty && control.isEmpty }
    }

    init() throws {
        // Fail loud on syscall failure (fd exhaustion — EMFILE/ENFILE): a `-1` kq would make every
        // `kevent` silently no-op, leaving the server accepting connections it never serves. Surfaced as a
        // `TransportError` so `start()` (already `throws`) reports it instead of going silently dark.
        let fd = kqueue()
        guard fd >= 0 else {
            throw TransportError.ioFailed("kqueue failed (errno \(errno))")
        }
        kq = fd
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Starts the run loop on its dedicated thread (one long-running block, not a re-scheduled poll).
    func start() {
        thread.async { [self] in
            registerWakeup()
            runLoop()
        }
    }

    /// Stops the loop; the wakeup makes it exit this turn instead of waiting out the idle timeout.
    func stop() {
        registry.withLock { $0.isRunning = false }
        triggerWakeup()
    }

    // MARK: - TaskExecutor

    /// Enqueues a pinned task's job to run on the loop thread next turn, waking the loop only when the
    /// enqueue came from off-loop (an on-loop resume is drained by the current turn — no wakeup needed).
    func enqueue(_ job: consuming ExecutorJob) {
        let unowned = UnownedJob(job)
        let offLoop = inbox.withLock { inbox -> Bool in
            inbox.jobs.append(unowned)
            return !inbox.onLoop
        }
        if offLoop {
            triggerWakeup()
        }
    }

    // MARK: - Readiness registration

    /// Registers one-shot interest in `fd` becoming readable; `handler` runs once when it does.
    ///
    /// Returns `false` — with `handler` dropped, not retained — when the kernel refuses the
    /// registration (`EBADF`: `fd` was already closed by a concurrent ``closeDescriptor(_:)``, e.g. a
    /// cancelled receive that raced this park). The caller must then fail its parked waiter itself:
    /// parking behind a registration that can never fire would leak the continuation, and probing the
    /// fd instead could touch a descriptor *number* the kernel has since reused.
    @discardableResult
    func waitReadable(_ fd: Int32, _ handler: @escaping @Sendable () -> Void) -> Bool {
        let id = registry.withLock { $0.park(handler, fd: fd, direction: \.readHandlers) }
        guard register(fd: fd, filter: EVFILT_READ) else {
            registry.withLock { $0.unpark(id: id, fd: fd, direction: \.readHandlers) }
            return false
        }
        return true
    }

    /// Registers one-shot interest in `fd` becoming writable; `handler` runs once when it does.
    ///
    /// Returns `false` with `handler` dropped when the registration is refused — see
    /// ``waitReadable(_:_:)``.
    @discardableResult
    func waitWritable(_ fd: Int32, _ handler: @escaping @Sendable () -> Void) -> Bool {
        let id = registry.withLock { $0.park(handler, fd: fd, direction: \.writeHandlers) }
        guard register(fd: fd, filter: EVFILT_WRITE) else {
            registry.withLock { $0.unpark(id: id, fd: fd, direction: \.writeHandlers) }
            return false
        }
        return true
    }

    /// Drops any pending interest in `fd` and closes it **on the loop thread**, so a close never races an
    /// in-flight handler and the fd number cannot be reused under one.
    func closeDescriptor(_ fd: Int32) {
        enqueueClose(fd, then: nil)
    }

    /// Closes `fd` on the loop thread and runs `completion` there, strictly after `close(2)` returned.
    ///
    /// The ordering is the whole point, and it is what lets a caller make an asynchronous close
    /// *synchronous*: a listener's `shutdown()` suspends on a continuation this completion resumes, so
    /// it cannot return while the listening descriptor is still open. Without it `shutdown()` merely
    /// enqueued the close and returned, and an immediate rebind of the same port raced it — `bind(2)`
    /// answering `EADDRINUSE` (errno 48 on Darwin, 98 on Linux; POSIX.1-2017 gives the listening socket
    /// the address until it is closed), i.e. a server that stops and restarts could fail to come back.
    ///
    /// `completion` runs on the loop thread, after the parked waiters are resumed, so an assertion made
    /// inside it observes a state in which the descriptor is provably gone.
    func closeDescriptor(_ fd: Int32, then completion: @escaping @Sendable () -> Void) {
        enqueueClose(fd, then: completion)
    }

    /// How much control work (closes, cancels) is queued for the loop thread but not yet run.
    ///
    /// The seam that makes the synchronous-close contract machine-checkable: a test can park the loop
    /// thread, watch a caller's close land in the queue, and assert that the caller is *still suspended*
    /// at that point. Without it "shutdown waited" and "shutdown got lucky" are indistinguishable from
    /// outside, which is how the asynchronous close survived a green matrix.
    ///
    /// An `Atomic` mirror of `inbox.control.count` rather than a read of it, because this is meant to be
    /// polled in a tight loop: polling the `Mutex` instead starved the very enqueue the poller was
    /// waiting for, and the parked-loop test converged only when nothing else contended the CPU.
    var queuedControlWork: Int {
        controlBacklog.load(ordering: .acquiring)
    }

    private func enqueueClose(_ fd: Int32, then completion: (@Sendable () -> Void)?) {
        let offLoop = inbox.withLock { inbox -> Bool in
            controlBacklog.add(1, ordering: .releasing)
            inbox.control.append { [self] in
                let parked = registry.withLock {
                    ($0.readHandlers.removeValue(forKey: fd) ?? [])
                        + ($0.writeHandlers.removeValue(forKey: fd) ?? [])
                }
                close(fd)
                // Resume any waiter parked on this fd so a cancelled (or otherwise closed) receive/send
                // does not leak its continuation: invoked after `close`, the handler's read/write hits
                // EBADF and resumes with an error instead of hanging (the cancel-deadlock the
                // backbone-conformance suite guards).
                for waiter in parked {
                    waiter.handler()
                }
                completion?()
            }
            return !inbox.onLoop
        }
        if offLoop {
            triggerWakeup()
        }
    }

    // MARK: - The run loop

    private func runLoop() {
        var events = [KEvent](repeating: KEvent(), count: 256)
        // The drain's double buffer, owned by the loop thread for its whole life. Swapped with the
        // inbox's arrays under the lock so BOTH stay uniquely referenced and their capacity is
        // genuinely reused — see ``drainInbox(jobs:control:until:)``.
        var jobs: [UnownedJob] = []
        var control: [@Sendable () -> Void] = []
        while registry.withLock(\.isRunning) {
            // Wait for readiness, but return at once (timeout 0) when work is already queued so pinned
            // continuations are not delayed behind the idle poll. The idle timeout (50 ms) only bounds
            // shutdown latency on a quiet loop; a wakeup pre-empts it. Clearing `onLoop` and reading
            // `isEmpty` under one lock is the block-decision: it serializes with an off-loop enqueue so
            // work added the instant before we park still wakes us (no lost wakeup).
            let idle = inbox.withLock { inbox -> Bool in
                inbox.onLoop = false
                return inbox.isEmpty
            }
            var timeout = timespec(tv_sec: 0, tv_nsec: idle ? 50_000_000 : 0)
            let count = events.withUnsafeMutableBufferPointer { buffer in
                kevent(kq, nil, 0, buffer.baseAddress, Int32(buffer.count), &timeout)
            }
            // Back on the loop thread's processing region: on-loop callers (the pinned serve task)
            // now skip the wakeup, because this turn re-drains the inbox before parking again.
            inbox.withLock { $0.onLoop = true }
            if count > 0 {
                for index in 0 ..< Int(count) {
                    let event = events[index]
                    if Int32(event.filter) == EVFILT_USER {
                        continue  // a bare wakeup — its only job was to return us from `kevent`
                    }
                    dispatch(event)
                }
            }
            // Drain control + jobs until the loop is idle again — or until the fairness quantum runs
            // out: a read handler resumes a pinned continuation (→ a job), whose handler runs here and
            // may chain straight into write / the next read, all inline on this thread, until the
            // connection finally blocks on I/O. Unbounded, one saturating source starves every other
            // socket on this reactor (PERF-1); the budget makes readiness wait at most one quantum.
            let budget = ReactorQuantum.nanoseconds() &+ ReactorQuantum.drainNanoseconds
            while !inbox.withLock(\.isEmpty), registry.withLock(\.isRunning) {
                guard drainInbox(jobs: &jobs, control: &control, until: budget) else {
                    break  // over quantum; the remainder is back in the inbox, readiness goes first
                }
            }
        }
        // `isRunning` just went false (a concurrent `stop()`). The inner drain above is gated on
        // `isRunning` too, so a `closeDescriptor`/`enqueue` control-closure that raced the flip — landing
        // in the inbox in the instant between the outer loop's readiness check and this point — could be
        // skipped by that gate and left stranded, permanently parking whatever continuation it would have
        // resumed (the teardown-drain race behind the intermittent `GracefulDrainTests` hang: a live
        // connection's close never runs, so its `serve` task, and the server's whole shutdown task group,
        // never returns). One final UNCONDITIONAL drain closes that window: anything enqueued up to this
        // point is guaranteed to run — fd closed, continuation resumed — before the loop thread exits.
        while !inbox.withLock(\.isEmpty) {
            // No budget on the teardown drain: its whole purpose is that nothing is left stranded.
            _ = drainInbox(jobs: &jobs, control: &control, until: .max)
        }
        close(kq)
    }

    /// Runs one batch of the inbox on the loop thread; returns whether it finished within `budget`.
    ///
    /// `jobs`/`control` are the caller's long-lived double buffer. Swapping them with the inbox's
    /// arrays — rather than copying the arrays out and calling `removeAll(keepingCapacity:)` — is what
    /// makes the drain allocation-free in steady state: a copy leaves both the inbox's `var` and the
    /// local holding the same buffer, so the very next `removeAll` sees a non-unique reference and
    /// reallocates, defeating `keepingCapacity` on every single drain.
    ///
    /// Control work always runs in full and is never deferred by the budget: a close or cancel held
    /// back behind a job flood is a parked continuation left stranded, which is the teardown-drain hang
    /// the unconditional final drain exists to prevent.
    private func drainInbox(
        jobs: inout [UnownedJob],
        control: inout [@Sendable () -> Void],
        until budget: UInt64
    ) -> Bool {
        inbox.withLock { inbox in
            swap(&inbox.jobs, &jobs)
            swap(&inbox.control, &control)
            // Queued-but-not-yet-run: this batch is about to RUN, so it leaves the backlog here rather
            // than after the closures return — otherwise a closure that parks the loop would count
            // itself, and ``queuedControlWork`` would never read zero on a loop that is merely busy.
            controlBacklog.subtract(control.count, ordering: .releasing)
        }
        for closure in control {
            closure()
        }
        control.removeAll(keepingCapacity: true)

        var index = 0
        while index < jobs.count {
            // The clock is read once per stride, not per job: a `clock_gettime_nsec_np` is ~11 ns
            // against a ~19 us `kevent` round trip on this host, so the check is free at this
            // granularity while still bounding readiness starvation to roughly one quantum.
            let stride = min(jobs.count, index &+ ReactorQuantum.clockCheckStride)
            while index < stride {
                jobs[index].runSynchronously(on: asUnownedTaskExecutor())
                index &+= 1
            }
            if index < jobs.count, ReactorQuantum.nanoseconds() >= budget {
                break
            }
        }
        let finished = index == jobs.count
        if !finished {
            // Hand the tail back at the FRONT, so nothing is dropped and FIFO order holds across the
            // readiness turn this yields to. Allocating here is deliberate: it happens only when a
            // source is actually saturating the loop, which is the case the quantum exists to bound.
            let remainder = Array(jobs[index...])
            inbox.withLock { $0.jobs.insert(contentsOf: remainder, at: 0) }
        }
        jobs.removeAll(keepingCapacity: true)
        return finished
    }

    /// Resumes **every** waiter parked on this descriptor in this direction.
    ///
    /// Not just the newest: readiness is level information, so a waiter that finds the descriptor
    /// already drained by a peer simply gets `EAGAIN` and re-parks. Resuming one and forgetting the
    /// rest is what left continuations suspended forever.
    private func dispatch(_ event: KEvent) {
        let fd = Int32(event.ident)
        let waiters: [Waiter] = registry.withLock { registry in
            if Int32(event.filter) == EVFILT_READ {
                return registry.readHandlers.removeValue(forKey: fd) ?? []
            }
            if Int32(event.filter) == EVFILT_WRITE {
                return registry.writeHandlers.removeValue(forKey: fd) ?? []
            }
            return []
        }
        for waiter in waiters {
            waiter.handler()
        }
    }

    /// Adds a one-shot `EV_ADD` registration, reporting whether the kernel accepted it.
    ///
    /// `false` (`EBADF` after a concurrent close is the practical case) means no readiness event will
    /// ever fire for this registration — the caller unwinds the waiter it parked (see
    /// ``waitReadable(_:_:)``).
    private func register(fd: Int32, filter: Int32) -> Bool {
        var event = KEvent(
            ident: UInt(fd),
            filter: Int16(filter),
            flags: UInt16(EV_ADD | EV_ONESHOT),
            fflags: 0,
            data: 0,
            udata: nil
        )
        let accepted = kevent(kq, &event, 1, nil, 0, nil) >= 0
        // If the registration came from off-loop while the loop is parked in `kevent`, wake it so the
        // new interest is honored this turn. From the loop thread itself (the pinned serve task parking
        // on a read) the wakeup is pure overhead — the loop re-checks the readiness set before parking
        // again — so it is skipped (audit — per-request wakeup elimination).
        if inbox.withLock(\.onLoop) == false {
            triggerWakeup()
        }
        return accepted
    }

    /// Adds the `EVFILT_USER` wakeup source once, at loop start (`EV_CLEAR` = auto-reset each delivery).
    private func registerWakeup() {
        var event = KEvent(
            ident: Self.wakeIdent,
            filter: Int16(EVFILT_USER),
            flags: UInt16(EV_ADD | EV_CLEAR),
            fflags: 0,
            data: 0,
            udata: nil
        )
        _ = kevent(kq, &event, 1, nil, 0, nil)
    }

    /// Fires the `EVFILT_USER` source so a blocked `kevent` returns immediately (thread-safe).
    private func triggerWakeup() {
        var event = KEvent(
            ident: Self.wakeIdent,
            filter: Int16(EVFILT_USER),
            flags: 0,
            fflags: UInt32(NOTE_TRIGGER),
            data: 0,
            udata: nil
        )
        _ = kevent(kq, &event, 1, nil, 0, nil)
    }
}
