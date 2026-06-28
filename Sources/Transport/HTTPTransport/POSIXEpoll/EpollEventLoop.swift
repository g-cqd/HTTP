//
//  EpollEventLoop.swift
//  HTTPTransport
//
//  The Linux mirror of ``KqueueEventLoop``: a minimal hand-rolled `epoll(7)` readiness loop that
//  watches descriptors for one-shot read/write readiness and invokes the registered handler on its
//  background queue. Unlike kqueue (independent per-filter registrations), epoll keeps ONE registration
//  per fd carrying a combined event mask, so this tracks both handlers per fd and recomputes the mask
//  on each (re-)arm; `EPOLLONESHOT` gives the one-shot semantics `EV_ONESHOT` gives on kqueue.
//
//  Verified on Linux (Swift 6.5-dev, Ubuntu noble, aarch64) via apple/container: the library builds and
//  `httpd-example` on this backbone serves real HTTP/1.1 (GET/POST, path parameters, the middleware
//  chain) end to end. `epoll(7)` is absent on Darwin, so the file is gated `#if canImport(Glibc)` (it
//  compiles to nothing off Linux) and gets its epoll symbols from the `CEpoll` shim (the platform
//  `Glibc` module surfaces none). See Docs/Documentation/audit/2026-06-27-linux-readiness-audit.md.
//
//  Standards: epoll_create1()/epoll_ctl()/epoll_wait() are the Linux readiness primitives (epoll(7));
//  the descriptors they watch are POSIX.1-2017 TCP (RFC 9293) sockets.
//

#if canImport(Glibc)

    internal import CEpoll
    internal import Dispatch
    internal import Glibc
    internal import Synchronization

    /// A one-shot readiness multiplexer over Linux `epoll(7)` — the Linux mirror of ``KqueueEventLoop``.
    final class EpollEventLoop: Sendable {
        private let epfd: Int32
        private let queue = DispatchQueue(label: "http.transport.epoll.loop")
        private let registry = Mutex<Registry>(Registry())

        private struct Registry {
            var readHandlers: [Int32: @Sendable () -> Void] = [:]
            var writeHandlers: [Int32: @Sendable () -> Void] = [:]
            /// fds currently in the epoll set (so the next `arm` chooses `EPOLL_CTL_MOD` vs `_ADD`).
            var registered: Set<Int32> = []
            var isRunning = true
        }

        init() throws {
            // CLOEXEC keeps the epoll fd from leaking across a prefork `exec` (matches POSIXSocket hygiene).
            // Fail loud on syscall failure (fd exhaustion — EMFILE/ENFILE): a `-1` epfd would make every
            // `epoll_ctl`/`epoll_wait` silently no-op, leaving the server accepting connections it never
            // serves. Surfaced as a `TransportError` so `start()` (already `throws`) reports it.
            let fd = epoll_create1(Int32(EPOLL_CLOEXEC))
            guard fd >= 0 else {
                throw TransportError.ioFailed("epoll_create1 failed (errno \(errno))")
            }
            epfd = fd
        }

        deinit {
            // No teardown beyond ARC.
        }

        /// Starts the event loop on its background queue.
        ///
        /// Each poll re-schedules the next via `queue.async` (not a monopolizing `while`), so out-of-band
        /// work — notably ``closeDescriptor(_:)`` — runs between polls instead of being starved.
        func start() {
            scheduleNextPoll()
        }

        private func scheduleNextPoll() {
            queue.async { [weak self] in
                guard let self else {
                    return
                }
                guard registry.withLock(\.isRunning) else {
                    close(epfd)
                    return
                }
                pollOnce()
                scheduleNextPoll()
            }
        }

        /// Stops the loop; it exits within one poll interval.
        func stop() {
            registry.withLock { $0.isRunning = false }
        }

        /// Registers one-shot interest in `fd` becoming readable; `handler` runs once when it does.
        func waitReadable(_ fd: Int32, _ handler: @escaping @Sendable () -> Void) {
            registry.withLock { $0.readHandlers[fd] = handler }
            arm(fd)
        }

        /// Registers one-shot interest in `fd` becoming writable; `handler` runs once when it does.
        func waitWritable(_ fd: Int32, _ handler: @escaping @Sendable () -> Void) {
            registry.withLock { $0.writeHandlers[fd] = handler }
            arm(fd)
        }

        /// Drops any pending interest in `fd` and closes it on the loop's queue, so a close never races
        /// an in-flight handler and the fd number cannot be reused under one.
        func closeDescriptor(_ fd: Int32) {
            queue.async { [self] in
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
                // continuation: invoked after close, the handler's read/send hits EBADF and resumes with
                // an error instead of hanging (the kqueue backbone's `closeDescriptor` rationale).
                readHandler?()
                writeHandler?()
            }
        }

        /// (Re)arms `fd` for whichever directions currently have a pending handler, as a single
        /// `EPOLLONESHOT` registration — `EPOLL_CTL_ADD` the first time, `EPOLL_CTL_MOD` thereafter.
        private func arm(_ fd: Int32) {
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
            _ = epoll_ctl(epfd, alreadyRegistered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &event)
        }

        /// Polls once (a bounded `epoll_wait`) and dispatches ready handlers, then returns so the queue
        /// can run pending out-of-band work before the next poll.
        private func pollOnce() {
            // 50 ms bounds the latency of out-of-band work (close/cancel) and shutdown; readiness wakes
            // the wait immediately, so this caps only the idle path, not throughput (mirrors kqueue).
            var events = [epoll_event](repeating: epoll_event(), count: 64)
            let count = events.withUnsafeMutableBufferPointer { buffer -> Int32 in
                // `epoll_wait`'s buffer is non-optional on Linux; `baseAddress` is non-nil for a non-empty
                // buffer (count 64), but guard rather than force-unwrap per the no-`!` rule.
                guard let base = buffer.baseAddress else {
                    return 0
                }
                return epoll_wait(epfd, base, Int32(buffer.count), 50)
            }
            // 0 = timeout, < 0 = EINTR/error — the next poll retries.
            guard count > 0 else {
                return
            }
            for index in 0 ..< Int(count) {
                dispatch(events[index])
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
            // `EPOLLONESHOT` disarmed the whole fd; if a handler in the other direction is still pending
            // (or the fired handler re-armed itself), re-arm. `arm` recomputes the mask and a redundant
            // `MOD` with the same mask is harmless.
            let stillPending = registry.withLock {
                $0.readHandlers[fd] != nil || $0.writeHandlers[fd] != nil
            }
            if stillPending {
                arm(fd)
            }
        }
    }

#endif
