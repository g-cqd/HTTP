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

    /// The admission slot the accept loop charged for this connection before yielding it (audit F8);
    /// the server releases it when the serve loop ends.
    public let admissionTicket: AdmissionTicket?

    /// The connection's own ``KqueueEventLoop`` — a `TaskExecutor` — so the server pins this
    /// connection's serve task to the loop and runs read → handler → write inline on the loop thread,
    /// with no hop to the cooperative pool (audit R4).
    public var preferredTaskExecutor: (any TaskExecutor)? { eventLoop }

    private let descriptor: FileDescriptor
    private let eventLoop: KqueueEventLoop
    private let isClosed = Atomic<Bool>(false)
    /// A reusable receive buffer, overwritten each read, so the hot read path allocates no fresh chunk
    /// per `recv` (audit P1) and holds only what this peer has shown it needs (ADD-P2 — see
    /// ``ReceiveScratch``). `Mutex`-guarded because `read(2)` runs on the loop thread while the copy-out
    /// runs on the awaiting (pinned) task; the inbound ``DirectionOwner`` makes reads serial, so the
    /// lock is uncontended.
    private let scratch = Mutex(ReceiveScratch())
    /// The inbound direction and its sole operation owner (audit F-03).
    ///
    /// Covers the WHOLE receive — the opportunistic read, the parked wait, and the copy-out of a
    /// scratch the next read overwrites. Mirrors ``POSIXKqueueConnection``.
    private let receiveOwner = DirectionOwner<Int>()
    /// The outbound direction and its sole operation owner (audit F-03).
    ///
    /// Covers the whole send: the first write and every partial-write / `writev` / `sendfile` retry.
    /// Independent of ``receiveOwner`` — a parked receive never delays a send.
    private let sendOwner = DirectionOwner<Void>()

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
        // Deliberately no fd close here: `close()` routes the shutdown through the loop so the descriptor
        // closes exactly once, serialized against any in-flight readiness handler. The owner calls `close()`.
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
                return nil  // 0 == EOF
            }
            // Inside the ownership on purpose (audit F-03): the scratch holds THIS read's octets only
            // until the next read overwrites them, and the next receive cannot start until this returns.
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
    /// octets until the next `read` overwrites them, so the copy is correct only while this operation
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

    /// The octets this connection's receive scratch currently holds — the residency oracle (ADD-P2).
    var receiveScratchBytes: Int {
        scratch.withLock(\.residentBytes)
    }

    /// Writes all of `bytes`, re-arming on writability whenever the socket buffer is full.
    ///
    /// Owns the outbound direction for the whole operation — the first write and every partial-write
    /// retry (audit F-03) — so a second sender queues behind it rather than displacing its
    /// continuation and stranding a half-written response.
    public func send(_ bytes: [UInt8]) async throws {
        try await sendOwner.withOwnership { once in
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                guard claimSend(continuation, once) else {
                    return
                }
                writeRemaining(bytes: bytes, offset: 0, once: once)
            }
        }
    }

    /// Scatter-gather send: writes `head` then `body` in one `writev` syscall — no coalesce copy
    /// (audit #3 / L4) — re-arming on writability whenever the socket buffer fills.
    ///
    /// An empty `body` falls back to the single-buffer ``send(_:)``. That fallback runs BEFORE the
    /// direction is taken: ``DirectionOwner`` is not reentrant, and taking it here and again in
    /// ``send(_:)`` would deadlock the connection (CWE-833). No per-op cancellation handler on the
    /// write path: the server registers one ``cancel()`` for the whole connection (audit CC4), which
    /// closes the fd and unblocks a parked write.
    public func send(_ head: [UInt8], _ body: [UInt8]) async throws {
        guard !body.isEmpty else {
            try await send(head)
            return
        }
        try await sendOwner.withOwnership { once in
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                guard claimSend(continuation, once) else {
                    return
                }
                writevRemaining(head: head, body: body, offset: 0, once: once)
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
    /// `file` (never closed here) and has already framed exactly `length` octets. swift-system has no
    /// typed `sendfile`, so the raw syscall takes the descriptor's `rawValue` (as `writev` does).
    public func sendFile(descriptor file: Int32, offset: Int, length: Int) async throws {
        guard length > 0 else {
            return
        }
        try await sendOwner.withOwnership { once in
            try await withUnsafeThrowingContinuation {
                (continuation: UnsafeContinuation<Void, any Error>) in
                guard claimSend(continuation, once) else {
                    return
                }
                sendFileRemaining(file: file, offset: offset, remaining: length, once: once)
            }
        }
    }

    /// One event-driven `sendfile(2)` pump step, on the loop thread.
    ///
    /// Darwin semantics: `-1`/`EAGAIN` with the partial count in `len`; `EINTR` likewise reports
    /// the progress made.
    private func sendFileRemaining(
        file: Int32, offset: Int, remaining: Int, once: OnceResumer<Void>
    ) {
        var offset = offset
        var remaining = remaining
        while remaining > 0 {
            var span = off_t(remaining)
            let result = sendfile(file, descriptor.rawValue, off_t(offset), &span, nil, 0)
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
                let registered = eventLoop.waitWritable(descriptor.rawValue) { [self] in
                    sendFileRemaining(
                        file: file, offset: nextOffset, remaining: nextRemaining, once: once
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

    /// One non-blocking `FileDescriptor.read` into the scratch: the byte count (`0` == EOF), or `nil`
    /// when the socket has nothing buffered yet (EAGAIN — the caller parks).
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
                // The window is what this peer has shown it needs, not the caller's ceiling (ADD-P2).
                // SE-0458 (ADR 0009): the call is unsafe by the closure's pointer parameter. The
                // buffer is sized by ``ReceiveScratch`` immediately before the call and is valid for
                // exactly `raw.count` octets; it does not escape this closure.
                try unsafe buffer.read(ceiling: maxLength) { raw -> Int in
                    try Self.readOnce(descriptor, raw)
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
