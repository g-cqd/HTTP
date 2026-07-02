//
//  EpollEventLoop.swift
//  HTTPTransport
//
//  The Linux mirror of ``KqueueEventLoop`` (audit R4): a hand-rolled `epoll(7)` run loop that is ALSO a
//  `TaskExecutor`. One dedicated thread interleaves I/O readiness and task execution — each turn it
//  `epoll_wait`s, runs the ready read/write handlers, then drains the executor's task queue, all on the
//  same thread. Pinning a connection's serve task to this loop runs read → parse → respond → write
//  inline on the loop thread, with no hop to the cooperative pool (the median-latency win). N loops
//  (one per core) shard the work — see ``POSIXEpollTransport``.
//
//  Cross-thread wakeups use an `eventfd` (epoll's analogue of kqueue `EVFILT_USER`): enqueuing a job (or
//  a close/stop) from another thread writes the eventfd, whose `EPOLLIN` returns the blocked `epoll_wait`
//  at once instead of waiting out the idle timeout.
//
//  Unlike kqueue (independent per-filter registrations), epoll keeps ONE registration per fd carrying a
//  combined mask, so this tracks both handlers per fd and recomputes the mask on each (re-)arm;
//  `EPOLLONESHOT` gives the one-shot semantics `EV_ONESHOT` gives on kqueue.
//
//  Gated `#if canImport(Glibc)` (compiles to nothing off Linux); epoll symbols come from the `CEpoll`
//  shim. Verified on Linux for the pre-R4 loop; the R4 run-loop rewrite needs a Linux CI pass (the macOS
//  test suite exercises only the kqueue twin). See Docs/Documentation/audit/2026-06-27-linux-readiness-audit.md
//  and 2026-06-28-tail-latency-variance-audit.md.
//
//  Standards: epoll_create1()/epoll_ctl()/epoll_wait()/eventfd() are Linux primitives; the descriptors
//  they watch are POSIX.1-2017 TCP (RFC 9293) sockets.
//

#if canImport(Glibc)

    internal import CEpoll
    internal import Dispatch
    internal import Glibc
    internal import Synchronization

    /// An `epoll(7)` readiness multiplexer that doubles as a `TaskExecutor` so work pinned to it runs
    /// inline on the loop thread (audit R4) — the Linux mirror of ``KqueueEventLoop``.
    final class EpollEventLoop: Sendable, TaskExecutor {
        private let epfd: Int32
        /// An `eventfd` registered for `EPOLLIN`, written to wake a blocked `epoll_wait` from off-loop.
        private let wakeFD: Int32
        /// Owns the single loop thread: ``start()`` submits one block that runs ``runLoop()`` for the
        /// loop's lifetime. `.userInitiated` so the thread is scheduled promptly under CPU contention.
        private let thread = DispatchQueue(label: "http.transport.epoll.loop", qos: .userInitiated)
        private let registry = Mutex<Registry>(Registry())
        /// Work submitted from off-loop (executor jobs + control closures), drained each turn on the loop.
        private let inbox = Mutex<Inbox>(Inbox())

        private struct Registry {
            var readHandlers: [Int32: @Sendable () -> Void] = [:]
            var writeHandlers: [Int32: @Sendable () -> Void] = [:]
            /// fds currently in the epoll set (so the next `arm` chooses `EPOLL_CTL_MOD` vs `_ADD`).
            var registered: Set<Int32> = []
            var isRunning = true
        }

        private struct Inbox {
            /// Continuations of tasks pinned to this loop, run on the loop thread (the no-hop hot path).
            var jobs: [UnownedJob] = []
            /// Out-of-band control work (close/cancel) serialized against the readiness handlers.
            var control: [@Sendable () -> Void] = []
            var isEmpty: Bool { jobs.isEmpty && control.isEmpty }
        }

        init() throws {
            // CLOEXEC keeps these fds from leaking across a prefork `exec` (matches POSIXSocket hygiene).
            // Fail loud on syscall failure (fd exhaustion): a `-1` epfd would make every epoll call a
            // silent no-op, leaving the server accepting connections it never serves.
            let fd = epoll_create1(Int32(EPOLL_CLOEXEC))
            guard fd >= 0 else {
                throw TransportError.ioFailed("epoll_create1 failed (errno \(errno))")
            }
            epfd = fd
            // Through the CEpoll shim: Glibc's modulemap exposes neither <sys/eventfd.h> nor the
            // EFD_* flags on any current toolchain (the same gap as <sys/epoll.h> itself).
            let wake = CEpoll_eventfd(0, CEpoll_eventfd_wakeup_flags())
            guard wake >= 0 else {
                close(fd)
                throw TransportError.ioFailed("eventfd failed (errno \(errno))")
            }
            wakeFD = wake
            // Level-triggered EPOLLIN (no EPOLLONESHOT) so the wakeup source stays armed for the loop's life.
            var event = epoll_event()
            event.events = EPOLLIN.rawValue
            event.data.fd = wake
            _ = epoll_ctl(fd, EPOLL_CTL_ADD, wake, &event)
        }

        deinit {
            // No teardown beyond ARC.
        }

        /// Starts the run loop on its dedicated thread (one long-running block, not a re-scheduled poll).
        func start() {
            thread.async { [self] in
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
        /// registration (`EBADF`: `fd` was already closed by a concurrent ``closeDescriptor(_:)``,
        /// e.g. a cancelled receive that raced this park). The caller must then fail its parked
        /// waiter itself: parking behind a registration that can never fire would leak the
        /// continuation, and probing the fd instead could touch a descriptor *number* the kernel has
        /// since reused. Mirrors ``KqueueEventLoop/waitReadable(_:_:)``.
        @discardableResult
        func waitReadable(_ fd: Int32, _ handler: @escaping @Sendable () -> Void) -> Bool {
            registry.withLock { $0.readHandlers[fd] = handler }
            guard arm(fd) else {
                registry.withLock { _ = $0.readHandlers.removeValue(forKey: fd) }
                return false
            }
            triggerWakeup()
            return true
        }

        /// Registers one-shot interest in `fd` becoming writable; `handler` runs once when it does.
        ///
        /// Returns `false` with `handler` dropped when the registration is refused — see
        /// ``waitReadable(_:_:)``.
        @discardableResult
        func waitWritable(_ fd: Int32, _ handler: @escaping @Sendable () -> Void) -> Bool {
            registry.withLock { $0.writeHandlers[fd] = handler }
            guard arm(fd) else {
                registry.withLock { _ = $0.writeHandlers.removeValue(forKey: fd) }
                return false
            }
            triggerWakeup()
            return true
        }

        /// Drops any pending interest in `fd` and closes it **on the loop thread**, so a close never races
        /// an in-flight handler and the fd number cannot be reused under one.
        func closeDescriptor(_ fd: Int32) {
            inbox.withLock {
                $0.control.append { [self] in
                    let (readHandler, writeHandler) = registry.withLock { registry in
                        registry.registered.remove(fd)
                        return (
                            registry.readHandlers.removeValue(forKey: fd),
                            registry.writeHandlers.removeValue(forKey: fd)
                        )
                    }
                    // Remove before close (a closed fd auto-leaves the set, but explicit DEL is race-free).
                    _ = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nil)
                    close(fd)
                    // Resume any parked waiter so a cancelled/closed receive/send doesn't leak its
                    // continuation: invoked after close, the handler hits EBADF and resumes with an error.
                    readHandler?()
                    writeHandler?()
                }
            }
            triggerWakeup()
        }

        // MARK: - The run loop

        private func runLoop() {
            var events = [epoll_event](repeating: epoll_event(), count: 256)
            while registry.withLock(\.isRunning) {
                // Return at once (timeout 0) when work is queued so pinned continuations are not delayed
                // behind the idle poll; the 50 ms idle timeout only bounds shutdown latency on a quiet loop.
                let idle = inbox.withLock(\.isEmpty)
                let count = events.withUnsafeMutableBufferPointer { buffer -> Int32 in
                    guard let base = buffer.baseAddress else {
                        return 0
                    }
                    return epoll_wait(epfd, base, Int32(buffer.count), idle ? 50 : 0)
                }
                if count > 0 {
                    for index in 0 ..< Int(count) {
                        let event = events[index]
                        if event.data.fd == wakeFD {
                            drainWake()  // a bare wakeup — reset the eventfd counter and move on
                            continue
                        }
                        dispatch(event)
                    }
                }
                while !inbox.withLock(\.isEmpty), registry.withLock(\.isRunning) {
                    drainInbox()
                }
            }
            close(wakeFD)
            close(epfd)
        }

        private func drainInbox() {
            let (jobs, control) = inbox.withLock {
                inbox -> ([UnownedJob], [@Sendable () -> Void]) in
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

        private func dispatch(_ event: epoll_event) {
            let fd = event.data.fd
            let ready = event.events
            // A hangup/error wakes both directions so a parked read/send completes (read→EOF, send→EPIPE).
            let hangup = ready & (EPOLLHUP.rawValue | EPOLLERR.rawValue) != 0
            let isReadable = hangup || (ready & EPOLLIN.rawValue != 0)
            let isWritable = hangup || (ready & EPOLLOUT.rawValue != 0)
            let (readHandler, writeHandler) = registry.withLock { registry in
                (
                    isReadable ? registry.readHandlers.removeValue(forKey: fd) : nil,
                    isWritable ? registry.writeHandlers.removeValue(forKey: fd) : nil
                )
            }
            readHandler?()
            writeHandler?()
            // `EPOLLONESHOT` disarmed the whole fd; re-arm if a handler in the other direction is still
            // pending (or the fired handler re-armed itself). A redundant `MOD` with the same mask is
            // fine. A refused re-arm (the fd died under us) fails the still-parked handlers here — on
            // the loop thread, serialized with the close sweep — so no waiter leaks behind it.
            let stillPending = registry.withLock {
                $0.readHandlers[fd] != nil || $0.writeHandlers[fd] != nil
            }
            if stillPending, !arm(fd) {
                let (stranded, strandedWrite) = registry.withLock {
                    (
                        $0.readHandlers.removeValue(forKey: fd),
                        $0.writeHandlers.removeValue(forKey: fd)
                    )
                }
                stranded?()
                strandedWrite?()
            }
        }

        /// (Re)arms `fd` for whichever directions currently have a pending handler, as a single
        /// `EPOLLONESHOT` registration — `EPOLL_CTL_ADD` the first time, `EPOLL_CTL_MOD` thereafter.
        ///
        /// Returns whether the kernel accepted the registration; on a refused first `ADD` the fd is
        /// dropped from `registered` again so a later attempt retries the `ADD`.
        private func arm(_ fd: Int32) -> Bool {
            let (mask, alreadyRegistered): (UInt32, Bool) = registry.withLock { registry in
                var events = EPOLLONESHOT.rawValue
                if registry.readHandlers[fd] != nil { events |= EPOLLIN.rawValue }
                if registry.writeHandlers[fd] != nil { events |= EPOLLOUT.rawValue }
                let was = registry.registered.contains(fd)
                registry.registered.insert(fd)
                return (events, was)
            }
            var event = epoll_event()
            event.events = mask
            event.data.fd = fd
            let operation = alreadyRegistered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD
            let accepted = epoll_ctl(epfd, operation, fd, &event) >= 0
            if !accepted, !alreadyRegistered {
                registry.withLock { _ = $0.registered.remove(fd) }
            }
            return accepted
        }

        /// Resets the `eventfd` counter after a wakeup (EFD_NONBLOCK, so this never blocks).
        private func drainWake() {
            var counter: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &counter) { read(wakeFD, $0.baseAddress, 8) }
        }

        /// Writes the `eventfd` so a blocked `epoll_wait` returns immediately (thread-safe).
        private func triggerWakeup() {
            var one: UInt64 = 1
            _ = withUnsafeBytes(of: &one) { write(wakeFD, $0.baseAddress, 8) }
        }
    }

#endif
