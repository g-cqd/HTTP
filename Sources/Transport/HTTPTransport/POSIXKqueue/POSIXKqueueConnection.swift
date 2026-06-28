//
//  POSIXKqueueConnection.swift
//  HTTPTransport
//
//  A TransportConnection driven entirely by a hand-rolled kqueue event loop over a non-blocking
//  socket: reads wait for EVFILT_READ then read() what is available; writes loop until drained,
//  re-arming on EVFILT_WRITE whenever the socket buffer fills. The write re-arm is event-driven
//  (each step runs on a fresh kqueue callback) — it is NOT stack recursion, so hostile peers cannot
//  grow the stack.
//
//  Standards: read()/write()/close() per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP (RFC 9293) over
//  IPv4 (RFC 791). Readiness via BSD kqueue.
//

internal import Darwin
internal import Synchronization

/// A ``TransportConnection`` whose readiness is multiplexed by a ``KqueueEventLoop``.
///
/// The descriptor and `Atomic` close flag are the only state; close is idempotent and serialized on
/// the event loop. Task cancellation closes the descriptor to unblock a pending read.
public final class POSIXKqueueConnection: TransportConnection {
    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    /// The connection's own ``KqueueEventLoop`` — a `TaskExecutor` — so the server pins this
    /// connection's serve task to the loop and runs read → handler → write inline on the loop thread,
    /// with no hop to the cooperative pool (audit R4).
    public var preferredTaskExecutor: (any TaskExecutor)? { eventLoop }

    private let descriptor: Int32
    private let eventLoop: KqueueEventLoop
    private let isClosed = Atomic<Bool>(false)
    /// A reusable receive buffer, sized to `maxLength` on first use and overwritten each read, so the hot
    /// read path allocates no fresh chunk per `recv` (audit P1). `Mutex`-guarded because `read(2)` runs on
    /// the event-loop thread while the copy-out runs on the awaiting task; reads on one connection are
    /// serial (the server awaits each before the next), so the lock is always uncontended.
    private let scratch = Mutex<[UInt8]>([])
    /// Cached resumer for the hot read path (``receive(into:)``).
    ///
    /// ``reset(_:)`` per op so the hot path allocates no fresh resumer (audit: tail-latency variance).
    /// Sound because reads on one connection are serialized — the prior continuation is always taken
    /// before the next op installs its own.
    private let readResumer = OnceResumer<Int>()
    /// Cached resumer for the hot write path (``send(_:)`` and the ``send(_:_:)`` writev override).
    ///
    /// Reused the same way: writes on one connection are serial and never overlap a read.
    private let writeResumer = OnceResumer<Void>()

    private enum WriteOutcome {
        case done
        case wouldBlock(offset: Int)
        case failed(errno: Int32)
    }

    /// Wraps an accepted, non-blocking socket descriptor watched by `eventLoop`.
    init(
        id: TransportConnectionID,
        descriptor: Int32,
        peer: TransportAddress,
        eventLoop: KqueueEventLoop
    ) {
        self.id = id
        self.peer = peer
        self.descriptor = descriptor
        self.eventLoop = eventLoop
    }

    deinit {
        // Deliberately no fd close here (audit F11): `close()` routes the shutdown through the event loop
        // so the descriptor is closed exactly once, serialized against any in-flight readiness handler — an
        // unsynchronized close would race a reuse of the fd number. `deinit` can run on any thread, so it
        // must not close directly. The owner (the accept loop's consumer) is responsible for calling
        // `close()`; dropping a connection without it leaks the fd.
    }

    /// Reads up to `maxLength` bytes once the socket is readable, or `nil` at end of stream.
    ///
    /// No per-op cancellation handler: the server registers one ``cancel()`` for the whole connection
    /// (audit CC4); cancelling the serve task closes the fd, which fires the parked readiness handler
    /// against the closed descriptor so this continuation resumes with an error instead of leaking.
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        let descriptor = self.descriptor
        let eventLoop = self.eventLoop
        return try await withUnsafeThrowingContinuation { continuation in
            let once = OnceResumer(continuation)
            eventLoop.waitReadable(descriptor) {
                Self.readAvailable(
                    descriptor: descriptor,
                    maxLength: maxLength,
                    eventLoop: eventLoop,
                    into: once
                )
            }
        }
    }

    /// Reads up to `maxLength` bytes into the reused scratch and appends them to `buffer`, returning the
    /// count appended (`0` at EOF) — the allocation-free read path (audit P1). `read(2)` fills the scratch
    /// in the readiness callback; the awaiting task then copies just the received bytes into `buffer`.
    public func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
        let count = try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Int, any Error>) in
            readResumer.reset(continuation)
            readIntoScratch(maxLength: maxLength, into: readResumer)
        }
        // The scratch holds the bytes `read(2)` produced (reads are serial, so it is undisturbed until
        // this copy); take just those into the caller's accumulator. `Mutex` borrows in place — no copy.
        if count > 0 {
            scratch.withLock { buffer.append(contentsOf: $0[..<count]) }
        }
        return count
    }

    /// Fills the reused scratch from `read(2)` once readable and resumes `once` with the byte count
    /// (`0` at EOF), re-arming on a spurious `EAGAIN` wakeup.
    ///
    /// Instance method so it can borrow the non-copyable `scratch` `Mutex`; `self` is captured only for
    /// the one-shot re-arm.
    private func readIntoScratch(maxLength: Int, into once: OnceResumer<Int>) {
        do {
            let bytesRead = try scratch.withLock { (buffer: inout [UInt8]) throws -> Int in
                if buffer.count < maxLength {
                    // Sized once on first use, then reused for the connection's lifetime.
                    buffer = [UInt8](repeating: 0, count: maxLength)
                }
                return try buffer.withUnsafeMutableBytes { raw -> Int in
                    while true {
                        let count = read(descriptor, raw.baseAddress, maxLength)
                        if count >= 0 {
                            return count
                        }
                        if errno == EINTR { continue }
                        if errno == EAGAIN || errno == EWOULDBLOCK { throw WouldBlockOnRead() }
                        throw TransportError.ioFailed("read errno \(errno)")
                    }
                }
            }
            once.resume(returning: bytesRead)  // 0 == EOF (a zero-length read)
        }
        catch is WouldBlockOnRead {
            eventLoop.waitReadable(descriptor) { [self] in
                readIntoScratch(maxLength: maxLength, into: once)
            }
        }
        catch {
            once.resume(throwing: error)
        }
    }

    /// Writes all of `bytes`, re-arming on writability whenever the socket buffer is full.
    public func send(_ bytes: [UInt8]) async throws {
        let descriptor = self.descriptor
        let eventLoop = self.eventLoop
        try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
            writeResumer.reset(continuation)
            Self.writeRemaining(
                bytes: bytes,
                offset: 0,
                descriptor: descriptor,
                eventLoop: eventLoop,
                once: writeResumer
            )
        }
    }

    /// Scatter-gather send: writes `head` then `body` in one `writev` syscall — no coalesce copy
    /// (audit #4 / L4) — re-arming on writability whenever the socket buffer fills.
    ///
    /// An empty `body` falls back to the single-buffer ``send(_:)``.
    public func send(_ head: [UInt8], _ body: [UInt8]) async throws {
        guard !body.isEmpty else {
            try await send(head)
            return
        }
        let descriptor = self.descriptor
        let eventLoop = self.eventLoop
        try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
            writeResumer.reset(continuation)
            Self.writevRemaining(
                head: head,
                body: body,
                offset: 0,
                descriptor: descriptor,
                eventLoop: eventLoop,
                once: writeResumer
            )
        }
    }

    /// Closes the descriptor (idempotent, serialized on the event loop to avoid an fd-reuse race).
    public func close() async {
        closeDescriptor()
    }

    /// Closes the descriptor synchronously to unblock a parked read/write (audit CC4) — the server's
    /// once-per-connection cancellation handler calls this; it is the idempotent ``closeDescriptor()``.
    public func cancel() {
        closeDescriptor()
    }

    private func closeDescriptor() {
        guard !isClosed.exchange(true, ordering: .acquiringAndReleasing) else {
            return
        }
        eventLoop.closeDescriptor(descriptor)
    }

    /// A non-blocking `read` reported it would block — re-arm readability rather than fail (audit T-F3).
    private struct WouldBlockOnRead: Error {}

    private static func readAvailable(
        descriptor: Int32,
        maxLength: Int,
        eventLoop: KqueueEventLoop,
        into once: OnceResumer<[UInt8]?>
    ) {
        do {
            let bytes = try POSIXSocket.readBuffer(maxLength: maxLength) { raw -> Int in
                while true {
                    let count = read(descriptor, raw.baseAddress, raw.count)
                    if count >= 0 {
                        return count
                    }
                    // EINTR: interrupted by a signal before any data — retry the read. EAGAIN: a
                    // spurious EVFILT_READ wakeup (data consumed elsewhere) — re-arm, don't fail.
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK { throw WouldBlockOnRead() }
                    throw TransportError.ioFailed("read errno \(errno)")
                }
            }
            once.resume(returning: bytes)  // nil == EOF (a zero-length read)
        }
        catch is WouldBlockOnRead {
            eventLoop.waitReadable(descriptor) {
                readAvailable(
                    descriptor: descriptor,
                    maxLength: maxLength,
                    eventLoop: eventLoop,
                    into: once
                )
            }
        }
        catch {
            once.resume(throwing: error)
        }
    }

    private static func writeRemaining(
        bytes: [UInt8],
        offset: Int,
        descriptor: Int32,
        eventLoop: KqueueEventLoop,
        once: OnceResumer<Void>
    ) {
        var offset = offset
        let outcome: WriteOutcome = bytes.withUnsafeBytes { raw in
            while offset < raw.count {
                let written = write(
                    descriptor,
                    raw.baseAddress?.advanced(by: offset),
                    raw.count - offset
                )
                if written > 0 {
                    offset += written
                }
                else if written < 0, errno == EINTR {
                    continue  // interrupted by a signal before any byte — retry (audit T-F3)
                }
                else if written < 0, errno == EWOULDBLOCK || errno == EAGAIN {
                    return .wouldBlock(offset: offset)
                }
                else {
                    return .failed(errno: errno)
                }
            }
            return .done
        }
        switch outcome {
            case .done:
                once.resume(returning: ())
            case .failed(let code):
                once.resume(throwing: TransportError.ioFailed("write errno \(code)"))
            case .wouldBlock(let remaining):
                eventLoop.waitWritable(descriptor) {
                    writeRemaining(
                        bytes: bytes,
                        offset: remaining,
                        descriptor: descriptor,
                        eventLoop: eventLoop,
                        once: once
                    )
                }
        }
    }

    /// Writes `head` then `body` via `writev`, advancing one combined offset across the two buffers and
    /// re-arming on writability when the socket buffer fills — iterative (event-driven), not recursive.
    private static func writevRemaining(
        head: [UInt8],
        body: [UInt8],
        offset: Int,
        descriptor: Int32,
        eventLoop: KqueueEventLoop,
        once: OnceResumer<Void>
    ) {
        var offset = offset
        let total = head.count + body.count
        let outcome: WriteOutcome = head.withUnsafeBytes { headRaw in
            body.withUnsafeBytes { bodyRaw in
                guard let headBase = headRaw.baseAddress, let bodyBase = bodyRaw.baseAddress else {
                    // Both buffers are non-empty by construction (body guarded, head is the status line).
                    return WriteOutcome.done
                }
                while offset < total {
                    // Gather vector for the unwritten tail: still within the head (head slice + whole
                    // body), or already past it (a body slice only).
                    var iovecs: [iovec]
                    if offset < head.count {
                        let headPtr = UnsafeMutableRawPointer(mutating: headBase + offset)
                        let bodyPtr = UnsafeMutableRawPointer(mutating: bodyBase)
                        iovecs = [
                            iovec(iov_base: headPtr, iov_len: head.count - offset),
                            iovec(iov_base: bodyPtr, iov_len: body.count)
                        ]
                    }
                    else {
                        let bodyOffset = offset - head.count
                        let bodyPtr = UnsafeMutableRawPointer(mutating: bodyBase + bodyOffset)
                        iovecs = [iovec(iov_base: bodyPtr, iov_len: body.count - bodyOffset)]
                    }
                    let written = writev(descriptor, &iovecs, Int32(iovecs.count))
                    if written > 0 {
                        offset += written
                    }
                    else if written < 0, errno == EINTR {
                        continue  // interrupted before any byte — retry (audit T-F3)
                    }
                    else if written < 0, errno == EWOULDBLOCK || errno == EAGAIN {
                        return .wouldBlock(offset: offset)
                    }
                    else {
                        return .failed(errno: errno)
                    }
                }
                return .done
            }
        }
        switch outcome {
            case .done:
                once.resume(returning: ())
            case .failed(let code):
                once.resume(throwing: TransportError.ioFailed("writev errno \(code)"))
            case .wouldBlock(let remaining):
                eventLoop.waitWritable(descriptor) {
                    writevRemaining(
                        head: head,
                        body: body,
                        offset: remaining,
                        descriptor: descriptor,
                        eventLoop: eventLoop,
                        once: once
                    )
                }
        }
    }
}
