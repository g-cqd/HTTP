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

    /// The `EVFILT_USER` identity used purely as a cross-thread wakeup (never a real fd).
    private static let wakeIdent = UInt(0xFFFF_FFF0)

    private struct Registry {
        var readHandlers: [Int32: @Sendable () -> Void] = [:]
        var writeHandlers: [Int32: @Sendable () -> Void] = [:]
        var isRunning = true
    }

    private struct Inbox {
        /// Continuations of tasks pinned to this loop, run on the loop thread (the no-hop hot path).
        var jobs: [UnownedJob] = []
        /// Out-of-band control work (close/cancel) that must run on the loop thread, serialized against
        /// the readiness handlers so a close never races an in-flight read/write on the same fd.
        var control: [@Sendable () -> Void] = []
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

    /// Enqueues a pinned task's job to run on the loop thread next turn, then wakes the loop.
    func enqueue(_ job: consuming ExecutorJob) {
        let unowned = UnownedJob(job)
        inbox.withLock { $0.jobs.append(unowned) }
        triggerWakeup()
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
        registry.withLock { $0.readHandlers[fd] = handler }
        guard register(fd: fd, filter: EVFILT_READ) else {
            registry.withLock { _ = $0.readHandlers.removeValue(forKey: fd) }
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
        registry.withLock { $0.writeHandlers[fd] = handler }
        guard register(fd: fd, filter: EVFILT_WRITE) else {
            registry.withLock { _ = $0.writeHandlers.removeValue(forKey: fd) }
            return false
        }
        return true
    }

    /// Drops any pending interest in `fd` and closes it **on the loop thread**, so a close never races an
    /// in-flight handler and the fd number cannot be reused under one.
    func closeDescriptor(_ fd: Int32) {
        inbox.withLock {
            $0.control.append { [self] in
                let (readHandler, writeHandler) = registry.withLock {
                    (
                        $0.readHandlers.removeValue(forKey: fd),
                        $0.writeHandlers.removeValue(forKey: fd)
                    )
                }
                close(fd)
                // Resume any waiter parked on this fd so a cancelled (or otherwise closed) receive/send
                // does not leak its continuation: invoked after `close`, the handler's read/write hits
                // EBADF and resumes with an error instead of hanging (the cancel-deadlock the
                // backbone-conformance suite guards).
                readHandler?()
                writeHandler?()
            }
        }
        triggerWakeup()
    }

    // MARK: - The run loop

    private func runLoop() {
        var events = [KEvent](repeating: KEvent(), count: 256)
        while registry.withLock(\.isRunning) {
            // Wait for readiness, but return at once (timeout 0) when work is already queued so pinned
            // continuations are not delayed behind the idle poll. The idle timeout (50 ms) only bounds
            // shutdown latency on a quiet loop; a wakeup pre-empts it.
            let idle = inbox.withLock(\.isEmpty)
            var timeout = timespec(tv_sec: 0, tv_nsec: idle ? 50_000_000 : 0)
            let count = events.withUnsafeMutableBufferPointer { buffer in
                kevent(kq, nil, 0, buffer.baseAddress, Int32(buffer.count), &timeout)
            }
            if count > 0 {
                for index in 0 ..< Int(count) {
                    let event = events[index]
                    if Int32(event.filter) == EVFILT_USER {
                        continue  // a bare wakeup — its only job was to return us from `kevent`
                    }
                    dispatch(event)
                }
            }
            // Drain control + jobs until the loop is idle again: a read handler resumes a pinned
            // continuation (→ a job), whose handler runs here and may chain straight into write / the
            // next read, all inline on this thread, until the connection finally blocks on I/O.
            while !inbox.withLock(\.isEmpty), registry.withLock(\.isRunning) {
                drainInbox()
            }
        }
        close(kq)
    }

    private func drainInbox() {
        let (jobs, control) = inbox.withLock { inbox -> ([UnownedJob], [@Sendable () -> Void]) in
            let taken = (inbox.jobs, inbox.control)
            inbox.jobs.removeAll(keepingCapacity: true)
            inbox.control.removeAll(keepingCapacity: true)
            return taken
        }
        for closure in control {
            closure()
        }
        for job in jobs {
            job.runSynchronously(on: asUnownedTaskExecutor())
        }
    }

    private func dispatch(_ event: KEvent) {
        let fd = Int32(event.ident)
        let handler: (@Sendable () -> Void)? = registry.withLock { registry in
            if Int32(event.filter) == EVFILT_READ {
                return registry.readHandlers.removeValue(forKey: fd)
            }
            if Int32(event.filter) == EVFILT_WRITE {
                return registry.writeHandlers.removeValue(forKey: fd)
            }
            return nil
        }
        handler?()
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
        // new interest is honored this turn. From the loop thread itself this is a cheap no-op trigger.
        triggerWakeup()
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
