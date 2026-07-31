//
//  POSIXDispatchConnection.swift
//  HTTPTransport
//
//  A TransportConnection over a non-blocking socket, driven by GCD `DispatchSource` readiness events
//  plus direct `read(2)`/`write(2)`. Unlike a `DispatchIO` channel — whose `read(length:)` operation
//  stays open until it has read the *full* length or hit EOF, so on a keep-alive socket it swallows the
//  next request's bytes and serializes the following read behind it — a readiness source consumes only
//  what is currently buffered and returns at once, which is exactly request/response framing needs.
//
//  Every descriptor access (read, write, close) runs on one per-connection *serial* queue, so a close
//  can never race a syscall on the same fd, and the fd is closed only after its source is cancelled.
//
//  Standards: the byte stream is TCP (RFC 9293) over IPv4 (RFC 791); read/write semantics follow
//  POSIX.1-2017 (IEEE Std 1003.1-2017).
//

internal import Darwin
internal import Dispatch
internal import Synchronization

/// A ``TransportConnection`` backed by GCD `DispatchSource` readiness over a non-blocking socket.
///
/// The `Atomic` close flag and the `Mutex`-guarded waiter make the type genuinely `Sendable`. Task
/// cancellation closes the descriptor, which unblocks (and fails) any parked read/write.
public final class POSIXDispatchConnection: TransportConnection {
    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    /// The admission slot the accept loop charged for this connection before yielding it (audit F8);
    /// the server releases it when the serve loop ends.
    public let admissionTicket: AdmissionTicket?

    private let descriptor: Int32
    private let queue: DispatchQueue
    private let isClosed = Atomic<Bool>(false)
    /// Parked read and write state, in ONE lock so teardown can take both atomically.
    ///
    /// They must be separate slots (2026-07-31 performance addendum, P0.2). HTTP/2 deliberately runs a
    /// continuous reader and a sole writer in *separate tasks*, so a read and a write parked at the same
    /// time is a supported state, not a contradiction. With one slot the later parker overwrote the
    /// earlier: the displaced source stayed armed but became unreachable from teardown, and the close
    /// sweep resumed at most one continuation — so one of the two operations never resumed at all.
    private let waiters = Mutex<Waiters>(Waiters())
    /// Cached resumer for the read path (``receive(maxLength:)`` — this backbone has no scratch override).
    ///
    /// ``reset(_:)`` per op so the hot path allocates no fresh resumer (audit: tail-latency variance).
    /// Sound because reads on one connection are serialized — the prior continuation is always taken
    /// before the next op installs its own.
    private let readResumer = OnceResumer<[UInt8]?>()
    /// Cached resumer for the write path (``send(_:)``).
    ///
    /// Reused the same way: writes on one connection are serialized against each other. They may,
    /// however, overlap a *read* — see ``waiters``.
    private let writeResumer = OnceResumer<Void>()

    /// How many directions currently have a parked waiter — 0, 1, or 2.
    ///
    /// Exposed for the P0.2 invariant: with a read and a write both parked this is 2. Under the former
    /// single-slot design it could only ever be 1, because the later parker overwrote the earlier. See
    /// ``waiters`` for why that mattered.
    var parkedDirectionCount: Int { waiters.withLock(\.parked).count }

    /// A parked read or write: its readiness source plus a closure that fails the awaiting continuation
    /// (read → EOF, write → error) when the connection is torn down out from under it.
    private struct Waiter {
        let source: any DispatchSourceProtocol
        let fail: @Sendable () -> Void
    }

    /// The connection's parked read and parked write, held together under one lock.
    private struct Waiters {
        var read: Waiter?
        var write: Waiter?

        var parked: [Waiter] { [read, write].compactMap(\.self) }
    }

    /// Counts parked sources down so the descriptor is closed exactly once — by the LAST cancel
    /// handler to run, since `DispatchSource.cancel()` is asynchronous and each armed source must
    /// quiesce before the fd can be reused.
    private final class CloseBarrier: Sendable {
        private let remaining: Mutex<Int>

        init(_ count: Int) {
            remaining = Mutex(count)
        }

        /// Whether this caller is the last to arrive.
        func arrive() -> Bool {
            remaining.withLock { value in
                value -= 1
                return value == 0
            }
        }

        deinit {
            // No teardown beyond ARC.
        }
    }

    /// Spurious readiness: the source fired but `read(2)` returned `EAGAIN`; keep waiting.
    private struct WouldBlock: Error {}

    /// Wraps an accepted, non-blocking socket; the connection owns and eventually closes `descriptor`.
    init(
        id: TransportConnectionID,
        descriptor: Int32,
        peer: TransportAddress,
        queue: DispatchQueue,
        admissionTicket: AdmissionTicket? = nil
    ) {
        self.id = id
        self.peer = peer
        self.descriptor = descriptor
        self.queue = queue
        self.admissionTicket = admissionTicket
    }

    deinit {
        // No teardown beyond ARC.
    }

    // MARK: - Receive

    /// Reads up to `maxLength` currently-buffered bytes, or `nil` at end of stream.
    ///
    /// Arms a read source; when the socket is readable, one non-blocking `read(2)` returns what is
    /// buffered.
    ///
    /// Honors per-call task cancellation (the ``TransportConnection`` receive contract): a per-read
    /// handler tears the connection down (``cancel()``), whose close sweep runs the parked waiter's
    /// `fail` closure; the lapse then surfaces as `CancellationError` rather than a bare EOF. Every
    /// receive on this backbone round-trips its serial queue anyway, so — unlike the loop-pinned
    /// backbones (audit CC4) — there is no handler-free hot path to preserve.
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        let fd = descriptor
        let bytes = try await withTaskCancellationHandler {
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<[UInt8]?, any Error>) in
                readResumer.reset(continuation)
                queue.async { [self] in
                    guard !isClosed.load(ordering: .acquiring) else {
                        readResumer.resume(returning: nil)
                        return
                    }
                    let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
                    waiters.withLock {
                        $0.read = Waiter(source: source) { [self] in
                            readResumer.resume(returning: nil)
                        }
                    }
                    source.setEventHandler { [self] in
                        do {
                            let bytes = try Self.readAvailable(fd, maxLength)
                            clearRead(source)
                            readResumer.resume(returning: bytes)
                        }
                        catch is WouldBlock {
                            // Spurious readiness — leave the source armed; it fires again.
                        }
                        catch {
                            clearRead(source)
                            readResumer.resume(throwing: error)
                        }
                    }
                    source.resume()
                }
            }
        } onCancel: {
            self.cancel()
        }
        // The close sweep resumes a parked read as EOF (`nil`); when that EOF was manufactured by this
        // task's own cancellation, report the standard signal instead of a fake end-of-stream.
        if bytes == nil {
            try Task.checkCancellation()
        }
        return bytes
    }

    /// One non-blocking `read(2)` of the bytes buffered now (`nil` at EOF); throws `WouldBlock` if the
    /// readiness was spurious so the caller keeps waiting.
    private static func readAvailable(_ fd: Int32, _ maxLength: Int) throws -> [UInt8]? {
        try POSIXSocket.readBuffer(maxLength: maxLength) { raw in
            while true {
                let count = read(fd, raw.baseAddress, raw.count)
                if count >= 0 {
                    return count
                }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { throw WouldBlock() }
                throw TransportError.ioFailed("read errno \(errno)")
            }
        }
    }

    // MARK: - Send

    /// Writes all of `bytes`, awaiting socket writability across short writes (backpressure).
    public func send(_ bytes: [UInt8]) async throws {
        guard !bytes.isEmpty else {
            return
        }
        let fd = descriptor
        try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
            writeResumer.reset(continuation)
            queue.async { [self] in
                guard !isClosed.load(ordering: .acquiring) else {
                    writeResumer.resume(throwing: TransportError.ioFailed("connection closed"))
                    return
                }
                writeFrom(0, fd: fd, bytes: bytes, once: writeResumer)
            }
        }
    }

    /// Writes `bytes[offset...]` with non-blocking `write(2)`; on `EAGAIN` arms a one-shot write source
    /// and resumes from the new offset once the socket drains — iterative (event-driven), not recursive.
    private func writeFrom(_ offset: Int, fd: Int32, bytes: [UInt8], once: OnceResumer<Void>) {
        let outcome: WriteOutcome = bytes.withUnsafeBytes { raw -> WriteOutcome in
            // Empty buffer (already guarded above).
            guard let base = raw.baseAddress else {
                return .done
            }
            var cursor = offset
            while cursor < raw.count {
                let written = write(fd, base + cursor, raw.count - cursor)
                if written > 0 {
                    cursor += written
                    continue
                }
                if written < 0 {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        return .wouldBlock(cursor)
                    }
                    return .failed(Int(errno))
                }
                return .wouldBlock(cursor)  // write returned 0
            }
            return .done
        }
        switch outcome {
            case .done:
                clearWrite(nil)
                once.resume(returning: ())
            case .failed(let code):
                clearWrite(nil)
                once.resume(throwing: TransportError.ioFailed("write errno \(code)"))
            case .wouldBlock(let next):
                let source = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: queue)
                waiters.withLock {
                    $0.write = Waiter(source: source) {
                        once.resume(throwing: TransportError.ioFailed("connection closed"))
                    }
                }
                source.setEventHandler { [self] in
                    source.cancel()  // one-shot; writeFrom re-arms if it blocks again
                    writeFrom(next, fd: fd, bytes: bytes, once: once)
                }
                source.resume()
        }
    }

    private enum WriteOutcome {
        case done
        case wouldBlock(Int)
        case failed(Int)
    }

    // MARK: - Close

    /// Closes the connection idempotently.
    public func close() async {
        closeDescriptor()
    }

    /// Closes the descriptor synchronously to unblock a parked read/write (audit CC4) — the server's
    /// once-per-connection cancellation handler calls this; it is the idempotent ``closeDescriptor()``.
    public func cancel() {
        closeDescriptor()
    }

    /// Clears the parked READ and cancels its completed `source` (called on `queue`).
    ///
    /// Direction-specific on purpose: clearing both slots would drop a concurrently parked write, which
    /// teardown would then never resume.
    private func clearRead(_ source: (any DispatchSourceProtocol)?) {
        waiters.withLock { $0.read = nil }
        source?.cancel()
    }

    /// Clears the parked WRITE and cancels its completed `source` (called on `queue`).
    private func clearWrite(_ source: (any DispatchSourceProtocol)?) {
        waiters.withLock { $0.write = nil }
        source?.cancel()
    }

    /// Closes the socket once, idempotently.
    ///
    /// `DispatchSource.cancel()` is asynchronous — a readiness handler the kernel just made ready may
    /// still be queued — so the fd is safe to close only once GCD has quiesced delivery, i.e. from the
    /// source's *cancellation handler*. Closing it inline after `cancel()` would race that handler onto
    /// a since-reused fd (cross-connection corruption). With no source armed there is no watcher, so an
    /// inline close is correct. Runs on `queue`.
    private func closeDescriptor() {
        guard !isClosed.exchange(true, ordering: .acquiringAndReleasing) else {
            return
        }
        let fd = descriptor
        queue.async { [self] in
            let parked = waiters.withLock { current -> [Waiter] in
                defer { current = Waiters() }
                return current.parked
            }
            guard !parked.isEmpty else {
                Darwin.close(fd)  // no armed source watching the fd → safe to close directly
                return
            }
            // Both directions may be parked at once, and EVERY armed source must quiesce before the fd
            // can be closed — otherwise a queued readiness handler could fire against a since-reused
            // descriptor. The barrier closes it on the last arrival; each waiter is failed regardless,
            // so neither a parked receive nor a parked send is left dangling.
            let barrier = CloseBarrier(parked.count)
            for waiter in parked {
                waiter.source.setCancelHandler {
                    if barrier.arrive() {
                        Darwin.close(fd)  // GCD guarantees delivery has stopped before this runs
                    }
                    waiter.fail()  // unblock the parked receive/send (EOF / error)
                }
                waiter.source.cancel()
            }
        }
    }
}
