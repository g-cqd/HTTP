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
    /// The inbound direction and its sole operation owner (audit F-03).
    ///
    /// This backbone has no scratch override, so the whole receive is the readiness wait plus the one
    /// `read(2)` its handler performs; a second receive queues behind it rather than displacing its
    /// continuation. Independent of ``sendOwner`` — see ``waiters`` for why a read and a write in
    /// flight together is a supported state, and ``DirectionOwner`` for why they must stay separate.
    private let receiveOwner = DirectionOwner<[UInt8]?>()
    /// The outbound direction and its sole operation owner (audit F-03).
    ///
    /// Covers the whole send: the first `write(2)` and every re-armed partial write until the payload
    /// is drained, and — through ``sendFile(descriptor:offset:length:)`` — every chunk of a file body.
    private let sendOwner = DirectionOwner<Void>()

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
        let bytes = try await receiveOwner.withOwnership { once in
            try await parkForRead(maxLength: maxLength, once: once)
        }
        // The close sweep resumes a parked read as EOF (`nil`); when that EOF was manufactured by this
        // task's own cancellation, report the standard signal instead of a fake end-of-stream.
        if bytes == nil {
            try Task.checkCancellation()
        }
        return bytes
    }

    /// Reads up to `maxLength` currently-buffered bytes and appends them to `buffer`, returning the
    /// count appended (`0` at EOF).
    ///
    /// Overridden rather than inherited (audit F-03). The default
    /// (``TransportConnection/receive(into:maxLength:)``) calls ``receive(maxLength:)`` and appends
    /// AFTER that call has released the inbound direction, which is the one shape this contract exists
    /// to forbid — the copy-out must be inside the lease that produced the octets, on every backbone,
    /// not only on the three that happen to read into a shared scratch. Here the chunk is freshly
    /// allocated per read, so today the released-lease append is merely out of order rather than
    /// corrupt; that is a property of this backbone's buffering, not of the contract, and it stops
    /// being true the moment this backbone is given the ``ReceiveScratch`` its three siblings have.
    public func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
        let appended = try await receiveOwner.withOwnership { once -> Int? in
            guard let bytes = try await parkForRead(maxLength: maxLength, once: once) else {
                return nil
            }
            appendReceived(bytes, to: &buffer)
            return bytes.count
        }
        // See ``receive(maxLength:)``: the close sweep resumes a parked read as EOF, and an EOF this
        // task's own cancellation manufactured is reported as the standard signal, not a short read.
        if appended == nil {
            try Task.checkCancellation()
        }
        return appended ?? 0
    }

    /// Appends the octets THIS read produced to `buffer`, in place — the copy-out, inside the lease.
    private func appendReceived(_ bytes: [UInt8], to buffer: inout [UInt8]) {
        assertInboundLeased("the copy-out")
        buffer.append(contentsOf: bytes)
    }

    /// Asserts the inbound direction is still leased, which is what makes the copy-out sound.
    ///
    /// The machine-checked half of the receive contract on this backbone (audit F-03), and the reason
    /// the override above exists at all: a behavioural test cannot prove a copy-out ran inside its
    /// lease, because it needs a second receive to actually interleave and about half the time none
    /// does. Mirrors ``POSIXKqueueConnection``'s `assertInboundLeased`.
    ///
    /// Kept a `precondition` rather than an `assert` so it holds in release: octets appended to a
    /// caller's buffer out of stream order are a silently desynchronized request body, not a crash.
    private func assertInboundLeased(_ step: StaticString) {
        precondition(
            receiveOwner.isOwned,
            "\(step) requires the inbound direction: it would take octets the owner never sees"
        )
    }

    /// Arms a read source and parks until it fires — the ungated core of ``receive(maxLength:)``.
    ///
    /// The caller already owns the inbound direction (audit F-03), and ``DirectionOwner`` is not
    /// reentrant, so this must never be reached through a gated entry point twice.
    private func parkForRead(maxLength: Int, once: OnceResumer<[UInt8]?>) async throws -> [UInt8]? {
        let fd = descriptor
        return try await withTaskCancellationHandler {
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<[UInt8]?, any Error>) in
                guard once.claim(continuation) else {
                    return  // contract broken; `claim` has already failed this caller
                }
                queue.async { [self] in
                    guard !isClosed.load(ordering: .acquiring) else {
                        once.resume(returning: nil)
                        return
                    }
                    armRead(fd: fd, maxLength: maxLength, once: once)
                }
            }
        } onCancel: {
            self.cancel()
        }
    }

    /// Registers read interest whose handler completes `once` with the bytes buffered when it fires.
    ///
    /// Runs on `queue`. A spurious readiness leaves the source armed; anything else clears the parked
    /// read (so teardown does not find a stale waiter) before resuming.
    private func armRead(fd: Int32, maxLength: Int, once: OnceResumer<[UInt8]?>) {
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        waiters.withLock {
            $0.read = Waiter(source: source) {
                once.resume(returning: nil)
            }
        }
        source.setEventHandler { [self] in
            do {
                // The syscall itself requires the lease, not only the copy-out that follows it: a
                // `read(2)` reached without the inbound direction takes octets off the stream that
                // the rightful owner then never sees, and a short read is indistinguishable from a
                // peer that sent less. Sound here because the owning task is suspended INSIDE
                // `withOwnership` while this handler runs, so the lease is still held; the close
                // sweep does not come through here, it runs the waiter's `fail` closure instead.
                assertInboundLeased("the read(2)")
                let bytes = try Self.readAvailable(fd, maxLength)
                clearRead(source)
                once.resume(returning: bytes)
            }
            catch is WouldBlock {
                // Spurious readiness — leave the source armed; it fires again.
            }
            catch {
                clearRead(source)
                once.resume(throwing: error)
            }
        }
        source.resume()
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
    ///
    /// Owns the outbound direction for the whole operation — the first `write(2)` and every re-armed
    /// partial write (audit F-03) — so a second sender queues behind it rather than displacing its
    /// continuation and stranding a half-written response.
    public func send(_ bytes: [UInt8]) async throws {
        guard !bytes.isEmpty else {
            return
        }
        try await sendOwner.withOwnership { once in
            try await writeOwned(bytes, once: once)
        }
    }

    /// Writes all of `bytes` — the ungated core of ``send(_:)``.
    ///
    /// The caller already owns the outbound direction, and ``DirectionOwner`` is not reentrant, so a
    /// gated entry point must call THIS rather than ``send(_:)`` (CWE-833). The close check runs on
    /// `queue`, after this operation has waited its turn: by then the descriptor may have been closed
    /// and its NUMBER reused by the kernel for an unrelated connection.
    private func writeOwned(_ bytes: [UInt8], once: OnceResumer<Void>) async throws {
        assertOutboundLeased()
        let fd = descriptor
        try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
            guard once.claim(continuation) else {
                return  // contract broken; `claim` has already failed this caller
            }
            queue.async { [self] in
                guard !isClosed.load(ordering: .acquiring) else {
                    once.resume(throwing: TransportError.ioFailed("connection closed"))
                    return
                }
                writeFrom(0, fd: fd, bytes: bytes, once: once)
            }
        }
    }

    /// Asserts the outbound direction is still leased, which is what keeps a send's octets contiguous.
    ///
    /// The machine-checked half of the send contract on this backbone (audit F-03). ``writeOwned`` is
    /// the sole send core — both ``send(_:)`` and ``sendFile(descriptor:offset:length:)`` drive it —
    /// and until now its only guard was ``OnceResumer/claim(_:)``, which is strictly weaker: `claim`
    /// fires only when a continuation is ALREADY pending, and between two `sendFile` chunks the slot
    /// is empty (the resumer hands the continuation out on resume). An ungated caller arriving in that
    /// window is admitted silently — precisely the per-chunk splice this override was written to close,
    /// reappearing as a refactor rather than as a design. Mirrors ``POSIXKqueueConnection``'s
    /// `claimSend` precondition; one uncontended lock read per chunk, not per partial write.
    private func assertOutboundLeased() {
        precondition(
            sendOwner.isOwned,
            "a send requires the outbound direction; octets would splice into another response"
        )
    }

    /// Sends `length` octets of the open file `file` from `offset`, holding the outbound direction for
    /// the WHOLE transfer rather than for each chunk.
    ///
    /// The inherited default (``TransportConnection/sendFile(descriptor:offset:length:)``) `pread`s
    /// into a bounded scratch and calls ``send(_:)`` per chunk, which under this contract would take
    /// and release the direction once per chunk — leaving a window between chunks for a concurrent
    /// sender to splice its octets into the middle of a file body. This override takes the direction
    /// once and drives the ungated ``writeOwned(_:once:)``; the copies are identical, the framing is
    /// not. `pread` (not `read`) so the caller's descriptor offset is never disturbed, and the loop
    /// never buffers more than one 64 KiB chunk regardless of file size.
    ///
    /// Standards: pread() per POSIX.1-2017 (IEEE Std 1003.1-2017).
    public func sendFile(descriptor file: Int32, offset: Int, length: Int) async throws {
        guard length > 0 else {
            return
        }
        try await sendOwner.withOwnership { once in
            var remaining = length
            var cursor = offset
            var chunk = [UInt8](repeating: 0, count: min(64 * 1_024, length))
            while remaining > 0 {
                let count = Self.preadChunk(file, &chunk, min(chunk.count, remaining), cursor)
                guard count > 0 else {
                    throw TransportError.ioFailed(
                        count == 0
                            ? "sendFile: file ended \(remaining) octet(s) short of the framed length"
                            : "sendFile: pread errno \(errno)"
                    )
                }
                try await writeOwned(Array(chunk[..<count]), once: once)
                cursor += count
                remaining -= count
            }
        }
    }

    /// One `pread(2)` of `wanted` octets into `chunk` at `cursor`, retrying `EINTR`; `-1` on failure.
    private static func preadChunk(
        _ file: Int32,
        _ chunk: inout [UInt8],
        _ wanted: Int,
        _ cursor: Int
    ) -> Int {
        chunk.withUnsafeMutableBytes { raw -> Int in
            while true {
                // SE-0458 (ADR 0009): unsafe by the pointer parameter. `raw` is this call's own buffer,
                // valid for at least `wanted` octets (`wanted <= chunk.count`), and does not escape.
                let read = unsafe pread(file, raw.baseAddress, wanted, off_t(cursor))
                if read >= 0 {
                    return read
                }
                if errno == EINTR {
                    continue
                }
                return -1
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
