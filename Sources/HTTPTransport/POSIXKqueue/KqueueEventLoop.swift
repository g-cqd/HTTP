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
    func start() {
        queue.async { [weak self] in
            self?.loop()
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
            registry.withLock {
                $0.readHandlers.removeValue(forKey: fd)
                $0.writeHandlers.removeValue(forKey: fd)
            }
            close(fd)
        }
    }

    private func register(fd: Int32, filter: Int32) {
        var event = KEvent(
            ident: UInt(fd), filter: Int16(filter), flags: UInt16(EV_ADD | EV_ONESHOT),
            fflags: 0, data: 0, udata: nil)
        _ = kevent(kq, &event, 1, nil, 0, nil)
    }

    private func loop() {
        var timeout = timespec(tv_sec: 0, tv_nsec: 200_000_000)  // 200 ms — bounds shutdown latency
        var events = [KEvent](repeating: KEvent(), count: 64)
        while registry.withLock({ $0.isRunning }) {
            let count = events.withUnsafeMutableBufferPointer { buffer in
                kevent(kq, nil, 0, buffer.baseAddress, Int32(buffer.count), &timeout)
            }
            if count < 0 {
                if errno == EINTR { continue }
                break
            }
            for index in 0..<Int(count) {
                dispatch(events[index])
            }
        }
        close(kq)
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
