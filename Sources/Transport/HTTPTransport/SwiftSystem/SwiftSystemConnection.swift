//
//  SwiftSystemConnection.swift
//  HTTPTransport
//
//  A TransportConnection over an accepted socket, using apple/swift-system's typed FileDescriptor for
//  read/write/close — driven **event-driven** by the shared ``KqueueEventLoop`` (audit R4), NOT by a
//  blocking syscall on a worker thread. The socket is non-blocking; a read/write that would block parks
//  on kqueue readiness and resumes on the loop thread, and the serve task is pinned to that loop
//  (``preferredTaskExecutor``) so read → parse → respond → write run inline with no hop to the
//  cooperative pool. This is the swift-system-typed twin of ``POSIXKqueueConnection``: it shows the
//  swift-system `FileDescriptor` API is not inherently blocking — the prior blocking model was a choice,
//  not a limitation — and it inherits the same median + tail profile as the kqueue backbone.
//
//  Task cancellation closes the descriptor through the loop (``closeDescriptor(_:)``), which unblocks a
//  parked read/write so the continuation resumes with an error instead of leaking.
//
//  Standards: read()/write()/close() per POSIX.1-2017 (IEEE Std 1003.1-2017) via swift-system's typed
//  wrappers; TCP (RFC 9293) over IPv4 (RFC 791). Readiness via BSD kqueue.
//

internal import Darwin
internal import Synchronization
internal import SystemPackage

/// A ``TransportConnection`` backed by a swift-system `FileDescriptor`, multiplexed by a
/// ``KqueueEventLoop`` (audit R4).
public final class SwiftSystemConnection: TransportConnection {
    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    /// The connection's own ``KqueueEventLoop`` — a `TaskExecutor` — so the server pins this
    /// connection's serve task to the loop and runs read → handler → write inline on the loop thread,
    /// with no hop to the cooperative pool (audit R4).
    public var preferredTaskExecutor: (any TaskExecutor)? { eventLoop }

    private let descriptor: FileDescriptor
    private let eventLoop: KqueueEventLoop
    private let isClosed = Atomic<Bool>(false)
    /// A reusable receive buffer, sized to `maxLength` on first use and overwritten each read, so the hot
    /// read path allocates no fresh chunk per `recv` (audit P1). `Mutex`-guarded because `read(2)` runs on
    /// the loop thread while the copy-out runs on the awaiting (pinned) task; reads on one connection are
    /// serial, so the lock is uncontended.
    private let scratch = Mutex<[UInt8]>([])
    /// Cached resumer for the shared scratch read core (both `receive` overloads).
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
        case failed(any Error)
    }

    /// A non-blocking `read`/`write` reported it would block — re-arm readiness rather than fail.
    private struct WouldBlock: Error {}

    /// Wraps an accepted, non-blocking socket `descriptor` watched by `eventLoop`.
    init(
        id: TransportConnectionID,
        descriptor: FileDescriptor,
        peer: TransportAddress,
        eventLoop: KqueueEventLoop
    ) {
        self.id = id
        self.peer = peer
        self.descriptor = descriptor
        self.eventLoop = eventLoop
    }

    deinit {
        // Deliberately no fd close here: `close()` routes the shutdown through the loop so the descriptor
        // closes exactly once, serialized against any in-flight readiness handler. The owner calls `close()`.
    }

    /// Reads up to `maxLength` bytes once the socket is readable, or `nil` at end of stream.
    ///
    /// Shares the reused-scratch read core with ``receive(into:maxLength:)`` (audit P1) — the returned
    /// chunk is the only per-read allocation — and honors per-call task cancellation (the
    /// ``TransportConnection`` receive contract).
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        let count = try await readIntoScratch(maxLength: maxLength)
        guard count > 0 else {
            return nil  // 0 == EOF
        }
        return scratch.withLock { Array($0[..<count]) }
    }

    /// Reads up to `maxLength` bytes into the reused scratch and appends them to `buffer`, returning the
    /// count appended (`0` at EOF) — the allocation-free read path (audit P1).
    public func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
        let count = try await readIntoScratch(maxLength: maxLength)
        if count > 0 {
            scratch.withLock { buffer.append(contentsOf: $0[..<count]) }
        }
        return count
    }

    /// Writes all of `bytes`, re-arming on writability whenever the socket buffer is full.
    public func send(_ bytes: [UInt8]) async throws {
        try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
            writeResumer.reset(continuation)
            writeRemaining(bytes: bytes, offset: 0, once: writeResumer)
        }
    }

    /// Scatter-gather send: writes `head` then `body` in one `writev` syscall — no coalesce copy
    /// (audit #3 / L4) — re-arming on writability whenever the socket buffer fills.
    ///
    /// An empty `body` falls back to the single-buffer ``send(_:)``. No per-op cancellation handler on
    /// the write path: the server registers one ``cancel()`` for the whole connection (audit CC4),
    /// which closes the fd and unblocks a parked write.
    public func send(_ head: [UInt8], _ body: [UInt8]) async throws {
        guard !body.isEmpty else {
            try await send(head)
            return
        }
        try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
            writeResumer.reset(continuation)
            writevRemaining(head: head, body: body, offset: 0, once: writeResumer)
        }
    }

    /// Closes the descriptor (idempotent, serialized on the loop to avoid an fd-reuse race).
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
        eventLoop.closeDescriptor(descriptor.rawValue)
    }

    /// The shared scratch read core: one opportunistic `FileDescriptor.read`, then — only when the
    /// socket has nothing buffered — the parked phase under a per-park cancellation handler.
    ///
    /// The two-phase split keeps the data-ready hot path free of cancellation bookkeeping (audit CC4)
    /// while a *parked* receive honors its own task's cancellation per the ``TransportConnection``
    /// contract: cancellation tears the connection down (``cancel()``), the loop's close sweep resumes
    /// the waiter, and the lapse surfaces here as `CancellationError`.
    private func readIntoScratch(maxLength: Int) async throws -> Int {
        do {
            if let immediate = try readScratchNow(maxLength: maxLength) {
                return immediate
            }
            return try await parkForScratchRead(maxLength: maxLength)
        }
        catch _ where Task.isCancelled {
            // The teardown above — or a pre-cancelled task finding the descriptor already closed —
            // surfaces as a transport error; report the standard cancellation signal instead.
            throw CancellationError()
        }
    }

    /// One non-blocking `FileDescriptor.read` into the scratch: the byte count (`0` == EOF), or `nil`
    /// when the socket has nothing buffered yet (EAGAIN — the caller parks).
    ///
    /// The close-flag guard runs first so a callback firing after ``cancel()`` — the loop's close
    /// sweep — never touches the descriptor *number*, which the kernel may already have reused for
    /// another connection.
    private func readScratchNow(maxLength: Int) throws -> Int? {
        guard !isClosed.load(ordering: .acquiring) else {
            throw TransportError.closed
        }
        do {
            return try scratch.withLock { (buffer: inout [UInt8]) throws -> Int in
                if buffer.count < maxLength {
                    buffer = [UInt8](repeating: 0, count: maxLength)  // sized once, then reused
                }
                return try buffer.withUnsafeMutableBytes { raw -> Int in
                    try Self.readOnce(
                        descriptor,
                        UnsafeMutableRawBufferPointer(rebasing: raw[..<maxLength])
                    )
                }
            }
        }
        catch is WouldBlock {
            return nil
        }
    }

    /// Parks until the socket is readable and resumes with the next read's outcome, under a
    /// cancellation handler that closes the connection — the only way to abandon an in-flight read on
    /// a byte stream without losing its framing (the ``TransportConnection`` receive contract).
    private func parkForScratchRead(maxLength: Int) async throws -> Int {
        try await withTaskCancellationHandler {
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Int, any Error>) in
                readResumer.reset(continuation)
                armScratchRead(maxLength: maxLength, into: readResumer)
            }
        } onCancel: {
            self.cancel()
        }
    }

    /// Registers read interest whose callback completes `once` with the next read — re-arming on a
    /// spurious `EAGAIN` wakeup — and fails `once` without touching the descriptor when the
    /// registration itself is refused (the descriptor was closed by a concurrent cancel).
    private func armScratchRead(maxLength: Int, into once: OnceResumer<Int>) {
        let registered = eventLoop.waitReadable(descriptor.rawValue) { [self] in
            do {
                guard let bytesRead = try readScratchNow(maxLength: maxLength) else {
                    armScratchRead(maxLength: maxLength, into: once)  // spurious wakeup — re-arm
                    return
                }
                once.resume(returning: bytesRead)  // 0 == EOF
            }
            catch {
                once.resume(throwing: error)
            }
        }
        if !registered {
            once.resume(throwing: TransportError.closed)
        }
    }

    /// One `FileDescriptor.read`, retrying `EINTR` and mapping `EAGAIN`/`EWOULDBLOCK` to ``WouldBlock``.
    private static func readOnce(
        _ descriptor: FileDescriptor,
        _ raw: UnsafeMutableRawBufferPointer
    ) throws -> Int {
        while true {
            do {
                return try descriptor.read(into: raw)
            }
            catch Errno.interrupted {
                continue  // signal before any byte — retry
            }
            catch let error as Errno
            where error == .wouldBlock || error == .resourceTemporarilyUnavailable {
                throw WouldBlock()  // spurious readiness / no data yet — re-arm
            }
        }
    }

    /// Writes `bytes[offset...]` via `FileDescriptor.write`; on `EAGAIN` re-arms writability and resumes
    /// from the new offset — iterative (event-driven), not recursive.
    ///
    /// Runs on the loop thread.
    private func writeRemaining(bytes: [UInt8], offset: Int, once: OnceResumer<Void>) {
        var offset = offset
        let outcome: WriteOutcome = bytes.withUnsafeBytes { raw in
            while offset < raw.count {
                do {
                    let written = try descriptor.write(
                        UnsafeRawBufferPointer(rebasing: raw[offset...])
                    )
                    offset += written
                }
                catch Errno.interrupted {
                    continue  // interrupted before any byte — retry
                }
                catch let error as Errno
                where error == .wouldBlock || error == .resourceTemporarilyUnavailable {
                    return .wouldBlock(offset: offset)
                }
                catch {
                    return .failed(error)
                }
            }
            return .done
        }
        switch outcome {
            case .done:
                once.resume(returning: ())
            case .failed(let error):
                once.resume(throwing: error)
            case .wouldBlock(let remaining):
                let registered = eventLoop.waitWritable(descriptor.rawValue) { [self] in
                    writeRemaining(bytes: bytes, offset: remaining, once: once)
                }
                if !registered {
                    // The descriptor died under us (a concurrent close/cancel raced this re-arm):
                    // fail the waiter rather than park behind a registration that can never fire.
                    once.resume(throwing: TransportError.closed)
                }
        }
    }

    /// Writes `head` then `body` via `writev`, advancing one combined offset across the two buffers and
    /// re-arming on writability when the socket buffer fills — iterative (event-driven), not recursive.
    ///
    /// swift-system has no typed `writev`, so the raw syscall takes the descriptor's `rawValue`; the
    /// socket's `SO_NOSIGPIPE` (set on accept — audit T-F1) keeps a peer RST mid-write from raising
    /// `SIGPIPE`. Runs on the loop thread.
    private func writevRemaining(
        head: [UInt8],
        body: [UInt8],
        offset: Int,
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
                    let written = writev(descriptor.rawValue, &iovecs, Int32(iovecs.count))
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
                        return .failed(TransportError.ioFailed("writev errno \(errno)"))
                    }
                }
                return .done
            }
        }
        switch outcome {
            case .done:
                once.resume(returning: ())
            case .failed(let error):
                once.resume(throwing: error)
            case .wouldBlock(let remaining):
                let registered = eventLoop.waitWritable(descriptor.rawValue) { [self] in
                    writevRemaining(head: head, body: body, offset: remaining, once: once)
                }
                if !registered {
                    // See ``writeRemaining``: never park behind a refused registration.
                    once.resume(throwing: TransportError.closed)
                }
        }
    }
}
