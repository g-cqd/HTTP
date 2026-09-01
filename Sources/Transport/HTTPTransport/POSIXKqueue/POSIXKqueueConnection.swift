//
//  POSIXKqueueConnection.swift
//  HTTPTransport
//
//  A TransportConnection driven entirely by a hand-rolled kqueue event loop over a non-blocking
//  socket: reads try one non-blocking read() and park on EVFILT_READ only when nothing is buffered;
//  writes loop until drained, re-arming on EVFILT_WRITE whenever the socket buffer fills. The write
//  re-arm is event-driven (each step runs on a fresh kqueue callback) — it is NOT stack recursion, so
//  hostile peers cannot grow the stack. A PARKED read honors its own task's cancellation (a per-park
//  handler tears the connection down — the TransportConnection receive contract); the data-ready hot
//  path carries no cancellation bookkeeping (audit CC4).
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

    /// The admission slot the accept loop charged for this connection before yielding it (audit F8);
    /// the server releases it when the serve loop ends.
    public let admissionTicket: AdmissionTicket?

    /// The connection's own ``KqueueEventLoop`` — a `TaskExecutor` — so the server pins this
    /// connection's serve task to the loop and runs read → handler → write inline on the loop thread,
    /// with no hop to the cooperative pool (audit R4).
    public var preferredTaskExecutor: (any TaskExecutor)? { eventLoop }

    private let descriptor: Int32
    private let eventLoop: KqueueEventLoop
    private let isClosed = Atomic<Bool>(false)
    /// A reusable receive buffer, overwritten each read, so the hot read path allocates no fresh chunk
    /// per `recv` (audit P1) and holds only what this peer has shown it needs (ADD-P2 — see
    /// ``ReceiveScratch``). `Mutex`-guarded because `read(2)` runs on the event-loop thread while the
    /// copy-out runs on the awaiting task; the inbound ``DirectionOwner`` makes reads serial, so the
    /// lock is always uncontended.
    private let scratch = Mutex(ReceiveScratch())
    /// The inbound direction and its sole operation owner (audit F-03).
    ///
    /// Covers the WHOLE receive — the opportunistic `read(2)`, the parked wait, and the copy-out of a
    /// scratch the next read overwrites — so a second receive queues behind this one instead of
    /// displacing its continuation. See ``DirectionOwner`` for why the two directions stay separate.
    private let receiveOwner = DirectionOwner<Int>()
    /// The outbound direction and its sole operation owner (audit F-03).
    ///
    /// Covers the whole send: the first `write(2)`/`writev(2)`/`sendfile(2)` and every partial-write
    /// retry until the payload is drained. Independent of ``receiveOwner`` — a parked receive never
    /// delays a send.
    private let sendOwner = DirectionOwner<Void>()

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
        eventLoop: KqueueEventLoop,
        admissionTicket: AdmissionTicket? = nil
    ) {
        self.id = id
        self.peer = peer
        self.descriptor = descriptor
        self.eventLoop = eventLoop
        self.admissionTicket = admissionTicket
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
    /// Shares the reused-scratch read core with ``receive(into:maxLength:)`` (audit P1) — the returned
    /// chunk is the only per-read allocation — and honors per-call task cancellation (the
    /// ``TransportConnection`` receive contract).
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        try await receiveOwner.withOwnership { once -> [UInt8]? in
            let count = try await readIntoScratch(maxLength: maxLength, once: once)
            guard count > 0 else {
                return nil  // 0 == EOF (a zero-length read)
            }
            return copyOutReceived(count)
        }
    }

    /// Reads up to `maxLength` bytes into the reused scratch and appends them to `buffer`, returning the
    /// count appended (`0` at EOF) — the allocation-free read path (audit P1).
    ///
    /// The append happens INSIDE the ownership (audit F-03): the scratch holds only THIS read's octets,
    /// until the next `read(2)` overwrites them, so a copy-out taken after the direction is released is
    /// a race rather than an optimization — the shape the 2026-07-31 audit found in the TLS twin under
    /// the same unenforced justification ("reads are serial"). `buffer` is captured by the non-escaping
    /// ownership body and appended to in place: no owned chunk hand-back, so no per-receive allocation.
    public func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
        try await receiveOwner.withOwnership { once in
            let count = try await readIntoScratch(maxLength: maxLength, once: once)
            if count > 0 {
                appendReceived(count, to: &buffer)
            }
            return count
        }
    }

    /// Copies out the octets THIS read produced, into a fresh chunk.
    private func copyOutReceived(_ count: Int) -> [UInt8] {
        assertInboundLeased("the scratch copy-out")
        return scratch.withLock { Array($0.received(count)) }
    }

    /// Appends the octets THIS read produced to `buffer`, in place — the allocation-free copy-out.
    private func appendReceived(_ count: Int, to buffer: inout [UInt8]) {
        assertInboundLeased("the scratch copy-out")
        scratch.withLock { buffer.append(contentsOf: $0.received(count)) }
    }

    /// Asserts the inbound direction is still leased, which is what makes a scratch copy-out sound.
    ///
    /// The reason both copy-outs route through a helper (audit F-03). The scratch holds one read's
    /// octets until the next `read(2)` overwrites them, so the copy is correct only while this operation
    /// still owns the direction — and a behavioural test cannot prove that: narrowing the lease so the
    /// copy-out happens after release was caught by the socket-level suite in only about half of its
    /// runs, because it needs a second receive to actually interleave. A test that only MAY interleave
    /// is not a regression test, so the invariant is machine-checked instead. Mirrors
    /// `PortableTLSConnection.drainCiphertext`'s `precondition(sendPump.isHeld)`.
    ///
    /// One uncontended lock read per receive, kept in release rather than an `assert` because a scratch
    /// copied out from under its owner is silent corruption of a request body, not a crash.
    private func assertInboundLeased(_ step: StaticString) {
        precondition(
            receiveOwner.isOwned,
            "\(step) requires the inbound direction: it would take octets the owner never sees"
        )
    }

    /// The receives queued behind the inbound owner — the deterministic contention oracle (F-03).
    ///
    /// Lets a test assert AT the contended moment rather than sleep and hope to catch it. The nine
    /// original ownership tests sequence their setup with a fixed sleep; the cancellation matrix
    /// cannot, because the whole question is WHERE in the operation the cancel lands.
    var queuedReceives: Int { receiveOwner.queuedOperations }

    /// Suspends until at least `count` receives are queued behind the inbound owner.
    func waitForQueuedReceives(atLeast count: Int) async throws {
        try await receiveOwner.waitForQueued(atLeast: count)
    }

    /// Suspends until at least `count` sends are queued behind the outbound owner.
    func waitForQueuedSends(atLeast count: Int) async throws {
        try await sendOwner.waitForQueued(atLeast: count)
    }

    /// Whether the inbound direction is leased right now — the exactly-one-owner oracle.
    var isReceiving: Bool { receiveOwner.isOwned }

    /// The octets this connection's receive scratch currently holds — the residency oracle (ADD-P2).
    var receiveScratchBytes: Int {
        scratch.withLock(\.residentBytes)
    }

    /// The shared scratch read core: one opportunistic non-blocking `read(2)`, then — only when the
    /// socket has nothing buffered — the parked phase under a per-park cancellation handler.
    ///
    /// The two-phase split keeps the data-ready hot path free of cancellation bookkeeping (audit CC4)
    /// while a *parked* receive honors its own task's cancellation per the ``TransportConnection``
    /// contract: cancellation tears the connection down (``cancel()``), the loop's close sweep resumes
    /// the waiter, and the lapse surfaces here as `CancellationError`.
    ///
    /// The ungated core: the caller already owns the inbound direction (audit F-03), and ``DirectionOwner``
    /// is not reentrant, so this must never be reached through a gated entry point twice.
    private func readIntoScratch(maxLength: Int, once: OnceResumer<Int>) async throws -> Int {
        do {
            if let immediate = try readScratchNow(maxLength: maxLength) {
                return immediate
            }
            return try await parkForScratchRead(maxLength: maxLength, once: once)
        }
        catch _ where Task.isCancelled {
            // The teardown above — or a pre-cancelled task finding the descriptor already closed —
            // surfaces as a transport error; report the standard cancellation signal instead.
            throw CancellationError()
        }
    }

    /// One non-blocking `read(2)` into the scratch: the byte count (`0` == EOF), or `nil` when the
    /// socket has nothing buffered yet (EAGAIN — the caller parks).
    ///
    /// The close-flag guard runs first so a callback firing after ``cancel()`` — the loop's close
    /// sweep — never touches the descriptor *number*, which the kernel may already have reused for
    /// another connection.
    /// The syscall itself requires the lease, not only the copy-out that follows it.
    ///
    /// "A cancelled operation must not consume another's readiness" is the invariant, and this is
    /// where it would be broken: a `read(2)` reached without the inbound direction takes octets off
    /// the stream that the rightful owner then never sees, and a short read is indistinguishable
    /// from a peer that sent less — so the theft is silent at every layer above. Asserting at the
    /// copy-out alone was one step too late.
    ///
    /// Sound from the readiness callback too: the owning task is suspended INSIDE `withOwnership`
    /// while its handler runs, so the lease is still held. The close sweep does not come through
    /// here — it resumes the waiter directly.
    private func readScratchNow(maxLength: Int) throws -> Int? {
        assertInboundLeased("the read(2)")
        guard !isClosed.load(ordering: .acquiring) else {
            throw TransportError.closed
        }
        do {
            return try scratch.withLock { (buffer: inout ReceiveScratch) throws -> Int in
                // `raw.count`, never `maxLength`: the window is what this peer has shown it needs, and
                // a short read is indistinguishable to the caller from a peer that sent less (ADD-P2).
                // SE-0458 (ADR 0009): the call is unsafe by the closure's pointer parameter. The
                // buffer is sized by ``ReceiveScratch`` immediately before the call and is valid for
                // exactly `raw.count` octets; it does not escape this closure.
                try unsafe buffer.read(ceiling: maxLength) { raw -> Int in
                    while true {
                        let count = read(descriptor, raw.baseAddress, raw.count)
                        if count >= 0 {
                            return count
                        }
                        if errno == EINTR { continue }
                        if errno == EAGAIN || errno == EWOULDBLOCK { throw WouldBlockOnRead() }
                        throw TransportError.ioFailed("read errno \(errno)")
                    }
                }
            }
        }
        catch is WouldBlockOnRead {
            return nil
        }
    }

    /// Parks until the socket is readable and resumes with the next read's outcome, under a
    /// cancellation handler that closes the connection — the only way to abandon an in-flight read on
    /// a byte stream without losing its framing (the ``TransportConnection`` receive contract).
    private func parkForScratchRead(maxLength: Int, once: OnceResumer<Int>) async throws -> Int {
        try await withTaskCancellationHandler {
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Int, any Error>) in
                guard once.claim(continuation) else {
                    return  // contract broken; `claim` has already failed this caller
                }
                armScratchRead(maxLength: maxLength, into: once)
            }
        } onCancel: {
            self.cancel()
        }
    }

    /// Registers read interest whose callback completes `once` with the next read — re-arming on a
    /// spurious `EAGAIN` wakeup — and fails `once` without touching the descriptor when the
    /// registration itself is refused (the descriptor was closed by a concurrent cancel).
    private func armScratchRead(maxLength: Int, into once: OnceResumer<Int>) {
        let registered = eventLoop.waitReadable(descriptor) { [self] in
            do {
                guard let bytesRead = try readScratchNow(maxLength: maxLength) else {
                    armScratchRead(maxLength: maxLength, into: once)  // spurious wakeup — re-arm
                    return
                }
                once.resume(returning: bytesRead)  // 0 == EOF (a zero-length read)
            }
            catch {
                once.resume(throwing: error)
            }
        }
        if !registered {
            once.resume(throwing: TransportError.closed)
        }
    }

    /// Writes all of `bytes`, re-arming on writability whenever the socket buffer is full.
    ///
    /// Owns the outbound direction for the whole operation — the first `write(2)` and every
    /// partial-write retry (audit F-03) — so a second sender queues behind it rather than displacing
    /// its continuation and stranding a half-written response.
    public func send(_ bytes: [UInt8]) async throws {
        let descriptor = self.descriptor
        let eventLoop = self.eventLoop
        try await sendOwner.withOwnership { once in
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                guard claimSend(continuation, once) else {
                    return
                }
                Self.writeRemaining(
                    bytes: bytes,
                    offset: 0,
                    descriptor: descriptor,
                    eventLoop: eventLoop,
                    once: once
                )
            }
        }
    }

    /// Scatter-gather send: writes `head` then `body` in one `writev` syscall — no coalesce copy
    /// (audit #4 / L4) — re-arming on writability whenever the socket buffer fills.
    ///
    /// An empty `body` falls back to the single-buffer ``send(_:)``. That fallback runs BEFORE the
    /// direction is taken: ``DirectionOwner`` is not reentrant, and taking it here and again in
    /// ``send(_:)`` would deadlock the connection (CWE-833).
    public func send(_ head: [UInt8], _ body: [UInt8]) async throws {
        guard !body.isEmpty else {
            try await send(head)
            return
        }
        let descriptor = self.descriptor
        let eventLoop = self.eventLoop
        try await sendOwner.withOwnership { once in
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                guard claimSend(continuation, once) else {
                    return
                }
                Self.writevRemaining(
                    head: head,
                    body: body,
                    offset: 0,
                    descriptor: descriptor,
                    eventLoop: eventLoop,
                    once: once
                )
            }
        }
    }

    /// Installs a send's continuation and reports whether the syscall may proceed.
    ///
    /// Two refusals, both of which have already resumed `continuation`: the ownership contract was
    /// broken (``OnceResumer/claim(_:)`` failed the intruder), or the connection was closed while this
    /// operation waited its turn. The close check matters most for a QUEUED send: by the time it owns
    /// the direction the descriptor may have been closed and its NUMBER reused by the kernel for an
    /// unrelated connection, and writing a response into that would be cross-connection corruption.
    ///
    /// The `precondition` is the machine-checked half of the contract on this side (audit F-03): every
    /// send entry point routes through here, so an ungated one — a gated method calling another gated
    /// method's core, or an exclusion removed in a later refactor — trips it deterministically rather
    /// than splicing its octets into another response's body. Mirrors
    /// `PortableTLSConnection.drainCiphertext`'s `precondition(sendPump.isHeld)`. One uncontended lock
    /// read per send, not per retry.
    private func claimSend(
        _ continuation: UnsafeContinuation<Void, any Error>,
        _ once: OnceResumer<Void>
    ) -> Bool {
        precondition(
            sendOwner.isOwned,
            "a send requires the outbound direction; octets would splice into another response"
        )
        // SE-0458 (ADR 0009): unsafe by the continuation parameter. `OnceResumer` stores and resumes
        // it under a `Mutex` that guarantees exactly one resumal; it does not escape this connection.
        guard unsafe once.claim(continuation) else {
            return false
        }
        guard !isClosed.load(ordering: .acquiring) else {
            once.resume(throwing: TransportError.closed)
            return false
        }
        return true
    }

    /// Sends `length` octets of the open file `file` starting at `offset` via Darwin `sendfile(2)` —
    /// the kernel moves file pages straight to the socket, no userspace copy (G5).
    ///
    /// Event-driven like ``send(_:)``: a partial send (`EAGAIN`, the socket buffer filled) re-arms on
    /// writability and resumes from the advanced offset — iterative, not recursive. The caller owns
    /// `file` (never closed here) and has already framed exactly `length` octets. Owns the outbound
    /// direction across every retry (audit F-03), so no other sender can splice octets into the body.
    public func sendFile(descriptor file: Int32, offset: Int, length: Int) async throws {
        guard length > 0 else {
            return
        }
        let socket = self.descriptor
        let eventLoop = self.eventLoop
        try await sendOwner.withOwnership { once in
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                guard claimSend(continuation, once) else {
                    return
                }
                Self.sendFileRemaining(
                    file: file,
                    offset: offset,
                    remaining: length,
                    socket: socket,
                    eventLoop: eventLoop,
                    once: once
                )
            }
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

    /// One event-driven `sendfile(2)` pump step: send as much of the remaining span as the socket
    /// buffer takes, re-arming on writability for the rest (Darwin semantics: `-1`/`EAGAIN` with the
    /// partial count in `len`; `EINTR` likewise reports the progress made).
    private static func sendFileRemaining(
        file: Int32,
        offset: Int,
        remaining: Int,
        socket: Int32,
        eventLoop: KqueueEventLoop,
        once: OnceResumer<Void>
    ) {
        var offset = offset
        var remaining = remaining
        while remaining > 0 {
            var span = off_t(remaining)
            let result = sendfile(file, socket, off_t(offset), &span, nil, 0)
            offset += Int(span)
            remaining -= Int(span)
            if result == 0 {
                continue  // the whole requested span was sent; the loop condition exits
            }
            if errno == EINTR {
                continue  // interrupted after `span` octets — retry the rest (audit T-F3)
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                // Immutable copies for the @Sendable re-arm closure.
                let nextOffset = offset
                let nextRemaining = remaining
                let registered = eventLoop.waitWritable(socket) {
                    sendFileRemaining(
                        file: file,
                        offset: nextOffset,
                        remaining: nextRemaining,
                        socket: socket,
                        eventLoop: eventLoop,
                        once: once
                    )
                }
                if !registered {
                    // See ``writeRemaining``: never park behind a refused registration.
                    once.resume(throwing: TransportError.closed)
                }
                return
            }
            once.resume(throwing: TransportError.ioFailed("sendfile errno \(errno)"))
            return
        }
        once.resume(returning: ())
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
                let registered = eventLoop.waitWritable(descriptor) {
                    writeRemaining(
                        bytes: bytes,
                        offset: remaining,
                        descriptor: descriptor,
                        eventLoop: eventLoop,
                        once: once
                    )
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
                let registered = eventLoop.waitWritable(descriptor) {
                    writevRemaining(
                        head: head,
                        body: body,
                        offset: remaining,
                        descriptor: descriptor,
                        eventLoop: eventLoop,
                        once: once
                    )
                }
                if !registered {
                    // See ``writeRemaining``: never park behind a refused registration.
                    once.resume(throwing: TransportError.closed)
                }
        }
    }
}
