//
//  KqueueEventLoop.swift
//  HTTPTransport
//
//  A minimal hand-rolled kqueue event loop: it watches descriptors for one-shot read/write
//  readiness and invokes the registered handler on its background queue. This is the core that
//  makes the kqueue backbone "closest to the hardware" — no GCD source, no DispatchIO.
//
//  Standards: kqueue()/kevent() are the BSD/Darwin readiness primitives (documented in the Darwin
//  manuals, not POSIX); the descriptors they watch are POSIX.1-2017 TCP (RFC 9293) sockets.
//

internal import Darwin
internal import Dispatch
internal import Synchronization

/// A one-shot readiness multiplexer over `kqueue`/`kevent`.
final class KqueueEventLoop: Sendable {
    /// Disambiguates the Darwin `kevent` *struct* from the `kevent()` *function* (same C name).
    private typealias KEvent = kevent

    private let kq: Int32
    private let queue = DispatchQueue(label: "http.transport.kqueue.loop")
    private let registry = Mutex<Registry>(Registry())

    private struct Registry {
        var readHandlers: [Int32: @Sendable () -> Void] = [:]
        var writeHandlers: [Int32: @Sendable () -> Void] = [:]
        var isRunning = true
    }

    init() {
        kq = kqueue()
    }

    /// Starts the event loop on its background queue.
    ///
    /// Each poll re-schedules the next via `queue.async` rather than spinning a `while` that
    /// monopolizes the serial queue — so out-of-band work submitted to the queue (notably
    /// ``closeDescriptor(_:)``, which unblocks a cancelled receive) runs between polls instead of
    /// being starved behind an endless loop.
    func start() {
        scheduleNextPoll()
    }

    private func scheduleNextPoll() {
        queue.async { [weak self] in
            guard let self else { return }
            guard registry.withLock(\.isRunning) else {
                close(kq)
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
        register(fd: fd, filter: EVFILT_READ)
    }

    /// Registers one-shot interest in `fd` becoming writable; `handler` runs once when it does.
    func waitWritable(_ fd: Int32, _ handler: @escaping @Sendable () -> Void) {
        registry.withLock { $0.writeHandlers[fd] = handler }
        register(fd: fd, filter: EVFILT_WRITE)
    }

    /// Drops any pending interest in `fd` and closes it on the loop's queue, so a close never races
    /// an in-flight handler and the fd number cannot be reused under one.
    func closeDescriptor(_ fd: Int32) {
        queue.async { [self] in
            let (readHandler, writeHandler) = registry.withLock {
                ($0.readHandlers.removeValue(forKey: fd), $0.writeHandlers.removeValue(forKey: fd))
            }
            close(fd)
            // Resume any waiter parked on this fd so a cancelled (or otherwise closed) receive/send
            // does not leak its continuation forever: invoked after `close`, the handler's read/write
            // hits EBADF and resumes with an error instead of hanging. Without this, cancelling a
            // stalled kqueue receive deadlocks — the bug the backbone-conformance suite surfaced.
            readHandler?()
            writeHandler?()
        }
    }

    private func register(fd: Int32, filter: Int32) {
        var event = KEvent(
            ident: UInt(fd), filter: Int16(filter), flags: UInt16(EV_ADD | EV_ONESHOT),
            fflags: 0, data: 0, udata: nil)
        _ = kevent(kq, &event, 1, nil, 0, nil)
    }

    /// Polls once for readiness (a bounded `kevent` wait) and dispatches any ready handlers, then
    /// returns so the queue can run pending out-of-band work before the next poll.
    private func pollOnce() {
        // 50 ms bounds the latency of out-of-band work (close/cancel) and of shutdown; readiness
        // wakes the poll immediately, so this timeout only caps the idle path, not throughput.
        var timeout = timespec(tv_sec: 0, tv_nsec: 50_000_000)
        var events = [KEvent](repeating: KEvent(), count: 64)
        let count = events.withUnsafeMutableBufferPointer { buffer in
            kevent(kq, nil, 0, buffer.baseAddress, Int32(buffer.count), &timeout)
        }
        guard count > 0 else { return }  // 0 = timeout, < 0 = EINTR/error — the next poll retries
        for index in 0 ..< Int(count) {
            dispatch(events[index])
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
}
