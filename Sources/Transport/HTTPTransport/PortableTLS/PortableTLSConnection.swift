//
//  PortableTLSConnection.swift
//  HTTPTransport
//
//  A ``TransportConnection`` backed by a libssl `SSL` over an accepted socket — **event-driven** via
//  memory BIOs on the shared kqueue/epoll loop (audit R4, ADR 0004's productionization path), the TLS
//  twin of ``POSIXKqueueConnection``. The earlier model bound a *blocking* `SSL_set_fd` on a
//  per-connection serial `DispatchQueue` (a thread per in-flight TLS op); this drives `SSL` through a
//  pair of memory `BIO`s instead: `SSL_read`/`SSL_write` move *plaintext* to/from the BIOs, and the
//  connection pumps *ciphertext* between those BIOs and a **non-blocking** socket using the shared
//  readiness loop — `SSL_ERROR_WANT_READ`/`WANT_WRITE` become "await more socket bytes / flush".
//
//  Two tasks share one connection by design, so nothing here may assume a single caller. Every HTTP/2
//  connection runs a continuous reader task alongside a sole writer, and an HTTP/1 WebSocket session
//  runs a reader task alongside its pump; the reader receives while the pump sends. The engine state
//  they both drive — one `SSL`, two memory BIOs, the ciphertext buffers — is therefore serialized
//  explicitly rather than by convention:
//
//  - ``engine`` is a `Mutex`-owned ``PortableTLSEngine``. BoringSSL's `ssl.h` states that "an |SSL| is
//    not thread-safe and may only be used on one thread at a time", with no reader/writer split, so
//    this is ONE lock over both directions. It is never held across an `await`.
//  - ``sendPump`` is an ``AsyncExclusion`` held for the whole of ``send(_:)`` and the whole outbound
//    drain, *including* the writability parks inside it. TLS records must reach the socket in BIO
//    order and unspliced (RFC 8446 §5.1), and `SSL_write` commits to a buffer across a retry, so this
//    exclusion has to survive a suspension — which is why a `Mutex` cannot serve.
//  - ``receivePump`` is the same for the read direction, and is held across the copy-out as well as
//    the decrypt (audit F-02) — otherwise a second receiver decrypts over the plaintext scratch a
//    first one is about to copy out, and the two callers disagree about a byte.
//
//  A park on *readability* holds only ``receivePump``, so a receive waiting on a silent peer never
//  blocks a send. A park on *writability* holds ``sendPump``, which a receive needs only when
//  ciphertext is actually owed to the socket; that wait is bounded by the peer draining TCP, and the
//  connection's idle watchdog reaps a peer that never does.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` (the opt-in `HTTP_PORTABLE_TLS` build).
//
//  Standards: TLS 1.3 (RFC 8446) + ALPN (RFC 7301) over a POSIX.1-2017 TCP (RFC 9293) socket; readiness
//  via BSD kqueue / Linux epoll.
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    internal import HTTPConcurrency
    internal import Synchronization

    /// The platform readiness loop the TLS connection rides — kqueue on Darwin, epoll on Linux. Both are
    /// `TaskExecutor`s with the same `waitReadable`/`waitWritable`/`closeDescriptor` surface (audit R4).
    #if canImport(Darwin)
        typealias TLSEventLoop = KqueueEventLoop
    #elseif canImport(Glibc)
        typealias TLSEventLoop = EpollEventLoop
    #endif

    /// A ``TransportConnection`` backed by a libssl `SSL` driven through memory BIOs on a shared
    /// readiness loop (audit R4).
    ///
    /// `@unchecked Sendable` because the `SSL`, its BIOs and their buffers live behind ``engine``'s
    /// `Mutex` and the two direction exclusions — see the file comment for which covers what. The
    /// earlier justification ("I/O is serial per connection") was not true of any HTTP/2 or WebSocket
    /// connection, which is what this serialization replaces.
    final class PortableTLSConnection: TransportConnection, @unchecked Sendable {
        /// One `pread` chunk of ``sendFile(descriptor:offset:length:)`` — the ceiling on how much file
        /// this connection buffers at once, whatever the body's size.
        private static let fileChunkOctets = 64 * 1_024

        let id: TransportConnectionID
        let peer: TransportAddress
        let isSecure = true

        /// The admission slot the accept thread charged for this connection **before** `SSL_new` and
        /// the handshake (audit F8), so a peer that connects and never sends a ClientHello still holds
        /// a slot against the ceiling.
        let admissionTicket: AdmissionTicket?

        var negotiatedApplicationProtocol: String? { negotiated.withLock(\.self) }
        var tlsPeerSubject: String? { tlsPeerIdentity?.subject }
        var tlsPeerIdentity: TLSPeerIdentity? { peerIdentity.withLock(\.self) }

        /// The loop is a `TaskExecutor`; pinning the serve task to it runs decrypt → handler → encrypt
        /// inline on the loop thread (audit R4).
        var preferredTaskExecutor: (any TaskExecutor)? { eventLoop }

        /// The `SSL` and both memory BIOs, with every call that touches them.
        ///
        /// One lock, both directions — see ``PortableTLSEngine`` for BoringSSL's own wording on why.
        private let engine: Mutex<PortableTLSEngine>
        /// Serializes the outbound direction across suspension points: one encrypter, one drainer.
        private let sendPump = AsyncExclusion()
        /// Serializes the inbound direction across suspension points: one decrypter, one copy-out.
        private let receivePump = AsyncExclusion()
        private let descriptor: Int32
        private let eventLoop: TLSEventLoop
        private let clientAuth: TransportTLS.ClientAuth
        private let verifyPeer: (@Sendable ([[UInt8]]) -> Bool)?
        private let isClosed = Atomic<Bool>(false)
        private let negotiated = Mutex<String?>(nil)
        /// The verified client-certificate identity (G3), captured once at handshake completion.
        private let peerIdentity = Mutex<TLSPeerIdentity?>(nil)

        init(
            id: TransportConnectionID,
            peer: TransportAddress,
            ssl: OpaquePointer,
            readBIO: UnsafeMutablePointer<BIO>,
            writeBIO: UnsafeMutablePointer<BIO>,
            descriptor: Int32,
            eventLoop: TLSEventLoop,
            clientAuth: TransportTLS.ClientAuth,
            verifyPeer: (@Sendable ([[UInt8]]) -> Bool)?,
            admissionTicket: AdmissionTicket? = nil
        ) {
            self.id = id
            self.peer = peer
            engine = Mutex(PortableTLSEngine(ssl: ssl, readBIO: readBIO, writeBIO: writeBIO))
            self.descriptor = descriptor
            self.eventLoop = eventLoop
            self.clientAuth = clientAuth
            self.verifyPeer = verifyPeer
            self.admissionTicket = admissionTicket
        }

        deinit {
            // Free the SSL (and, since `SSL_set_bio` transferred ownership, both memory BIOs) exactly
            // once — `release()` is idempotent. Safe on any thread: at deinit no reference remains, so
            // nothing can race the free.
            engine.withLock { $0.release() }
        }

        // MARK: - Handshake

        /// Drives the TLS handshake to completion through the memory BIOs, then captures the negotiated
        /// ALPN protocol and applies the client-auth (mutual TLS) trust policy — throwing on failure.
        func performHandshake() async throws {
            // The handshake drives both directions, so it holds the read exclusion for its duration and
            // takes the write exclusion per flush. Uncontended in practice (the transport handshakes
            // before publishing the connection), but the discipline is the same one every other path
            // follows rather than an assumption about the caller.
            try await receivePump.withExclusiveAccess { try await self.driveHandshake() }
            try applyHandshakeIdentity()
        }

        /// The `SSL_accept` loop of ``performHandshake()``.
        private func driveHandshake() async throws {
            while true {
                let outcome = engine.withLock { $0.acceptHandshake() }
                try await flushCiphertext()  // push any handshake records SSL produced
                switch outcome {
                    case .produced:
                        return
                    case .wantRead:
                        guard try await fillCiphertext() else {
                            throw TransportError.tlsConfigurationFailed("handshake EOF")
                        }
                    case .wantWrite:
                        try await awaitWritable()
                    case .closedByPeer, .transportEnded:
                        throw TransportError.tlsConfigurationFailed("handshake EOF")
                    case .failed(let status):
                        throw TransportError.tlsConfigurationFailed("SSL_accept error \(status)")
                }
            }
        }

        /// Captures ALPN and applies the client-auth trust policy once the handshake has completed.
        private func applyHandshakeIdentity() throws {
            negotiated.withLock { $0 = engine.withLock { $0.negotiatedProtocol() } }
            // Client-auth (G3): the TLS layer is permissive (`permissive_verify` always accepts), so the
            // `verifyPeer` hook is the *sole* validator of a presented chain. RFC 8446 §4.4.2.4 requires a
            // presented certificate to be validated — so a nil hook (no validator) **fails closed**:
            // an unvalidated chain MUST NOT be trusted (audit F4). An absent chain is allowed under
            // `.optional`/`.none` and unreachable under `.required` (the handshake already failed).
            let chain = engine.withLock { $0.peerChainDER() }
            let accepted =
                chain.isEmpty
                ? (clientAuth != .required)
                : (verifyPeer?(chain) ?? false)
            guard accepted else {
                throw TransportError.tlsConfigurationFailed(
                    "the client certificate was rejected by verifyPeer"
                )
            }
            guard !chain.isEmpty else {
                return
            }
            // The full verified identity (G3): DER chain + leaf subject + leaf SANs, captured once
            // here — off the byte path — and surfaced as request-scoped context.
            let subject = engine.withLock { $0.peerSubject() }
            peerIdentity.withLock { $0 = TLSPeerIdentity(chainDER: chain, subject: subject) }
        }

        // MARK: - Receive

        /// Receives up to `maxLength` decrypted bytes, or `nil` once the peer closes (TLS close-notify).
        ///
        /// The allocating spelling of ``receive(into:maxLength:)``, and literally that call: one
        /// receive path, so the lease discipline cannot be right in one and wrong in the other.
        func receive(maxLength: Int) async throws -> [UInt8]? {
            var chunk: [UInt8] = []
            let count = try await receive(into: &chunk, maxLength: maxLength)
            guard count > 0 else {
                return nil
            }
            return chunk
        }

        /// Reads up to `maxLength` decrypted bytes into the reused scratch and appends them to `buffer`
        /// (audit P1), returning the count appended (`0` once the peer closes).
        ///
        /// `buffer` is filled **inside** the exclusion, by the same engine acquisition that decrypted
        /// into the scratch (audit F-02). It used to be filled after the exclusion was released, on
        /// the stated grounds that "an `inout` parameter cannot be captured by a closure that spans a
        /// suspension point" — which is not true of a *non-escaping* closure, and ``withExclusiveAccess``
        /// takes one. The invariant that copy-out claimed instead — that no other decrypt can have run
        /// in between — was asserted by nothing: the release is what let a second receiver in.
        ///
        /// Cancellation and close are all-or-nothing here: the append happens only on the decrypt that
        /// returns, so a receive that throws (`CancellationError` from its own task, ``TransportError``
        /// from a closed descriptor) leaves `buffer` untouched rather than half-filled.
        func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
            try await receivePump.withExclusiveAccess {
                try await self.readPlaintext(into: &buffer, maxLength: maxLength)
            }
        }

        /// The octets this connection's plaintext scratch currently holds — the residency oracle.
        ///
        /// ADD-P2. ``ciphertextScratchBytes`` is the ciphertext pump's separate figure.
        var receiveScratchBytes: Int {
            engine.withLock { $0.plaintextResidentBytes() }
        }

        /// The octets this connection's two ciphertext pump buffers hold — `0` for a connection that
        /// has neither read nor written.
        var ciphertextScratchBytes: Int {
            engine.withLock { $0.ciphertextResidentBytes() }
        }

        /// Whether the outbound direction is currently claimed — the serialization oracle.
        ///
        /// Paired with ``isReceivePumpHeld``, this is how a caller checks that a completed exchange
        /// handed both directions back rather than stranding one, which no amount of commentary can.
        var isSendPumpHeld: Bool { sendPump.isHeld }

        /// Whether the inbound direction is currently claimed — see ``isSendPumpHeld``.
        var isReceivePumpHeld: Bool { receivePump.isHeld }

        /// Suspends until at least `count` senders are queued behind the current outbound holder.
        ///
        /// The deterministic sequencing hook for an ownership-SPAN assertion, and the reason the span
        /// tests are regression tests rather than coin flips: a test that starts a second sender and
        /// hopes it lands inside the window observes the interleaving perhaps half the time. This
        /// returns exactly when the contended state exists, so the assertion that follows is about a
        /// state the test established rather than one it wished for.
        func awaitQueuedSenders(atLeast count: Int) async throws {
            try await sendPump.waitForWaiters(atLeast: count)
        }

        /// `SSL_read` into the scratch and on into `sink`, pumping ciphertext from the socket on
        /// `WANT_READ` — the shared decrypt loop.
        ///
        /// Returns the plaintext byte count, or `0` at end of stream. A read torn down by its own
        /// task's cancellation (the ``TransportConnection`` receive contract — see ``awaitReadable()``)
        /// surfaces as `CancellationError`. The caller holds ``receivePump`` for the whole of this,
        /// copy-out included.
        private func readPlaintext(into sink: inout [UInt8], maxLength: Int) async throws -> Int {
            do {
                return try await decryptLoop(into: &sink, maxLength: maxLength)
            }
            catch _ where Task.isCancelled {
                // The teardown — or a pre-cancelled task finding the descriptor already closed —
                // surfaces as a transport error; report the standard cancellation signal instead.
                throw CancellationError()
            }
        }

        /// The decrypt loop body of ``readPlaintext(into:maxLength:)``.
        ///
        /// Every `await` below is a *retry* step — a ciphertext flush, a socket park — reached only
        /// when the engine produced no plaintext, so no suspension ever sits between an `SSL_read` and
        /// the copy-out of what it produced. That is why the loop can hold the lease across a park
        /// without holding the engine's `Mutex`: the two are different locks with different lifetimes.
        private func decryptLoop(into sink: inout [UInt8], maxLength: Int) async throws -> Int {
            while true {
                let outcome = engine.withLock { $0.decrypt(ceiling: maxLength, into: &sink) }
                switch outcome {
                    case .produced(let count):
                        return count
                    case .closedByPeer:
                        return 0  // clean TLS close-notify
                    case .transportEnded:
                        return 0  // abrupt peer EOF with nothing queued
                    case .wantRead:
                        // A renegotiation may owe the peer records first.
                        try await flushCiphertext()
                        guard try await fillCiphertext() else {
                            return 0  // socket EOF before close-notify — treat as end of stream
                        }
                    case .wantWrite:
                        try await awaitWritable()
                    case .failed(let status):
                        throw TransportError.ioFailed("SSL_read error \(status)")
                }
            }
        }

        // MARK: - Send

        /// Asserts the outbound direction is still leased, which is what keeps one response's octets
        /// contiguous and its TLS records unspliced.
        ///
        /// The machine-checked half of the send contract on this backbone. Both cores it guards —
        /// ``encryptAndDrain(_:)`` and ``drainCiphertext()`` — are ungated on purpose, because
        /// ``AsyncExclusion`` is not reentrant (CWE-833) and the gated entry points must call them
        /// directly. That split is exactly the shape a later refactor gets wrong: the per-chunk
        /// `sendFile` splice this backbone carried arrived by *inheriting* a default that called the
        /// gated ``send(_:)`` in a loop, and nothing failed. Now something does.
        ///
        /// One uncontended lock read per chunk — not per partial write. `precondition` rather than
        /// `assert`, so it holds in release: octets spliced into another response are silent
        /// corruption of a message body, not a crash. Mirrors ``POSIXDispatchConnection``'s
        /// `assertOutboundLeased` and the `assertInboundLeased` of all four POSIX backbones.
        private func assertOutboundLeased(_ step: StaticString) {
            precondition(
                sendPump.isHeld,
                "\(step) requires the outbound direction; records would splice without it"
            )
        }

        /// Encrypts and sends all of `bytes`, draining the produced ciphertext to the socket.
        ///
        /// The whole call runs under ``sendPump``. That is not belt-and-braces: `SSL_write` commits to
        /// its buffer when it cannot complete, and a retry that arrives with a *different* pointer is
        /// rejected with `SSL_R_BAD_WRITE_RETRY`, so a second sender interleaving here would fail one
        /// of the two — quite apart from the record splicing an interleaved drain would cause.
        func send(_ bytes: [UInt8]) async throws {
            guard !bytes.isEmpty else {
                return
            }
            try await sendPump.withExclusiveAccess { try await self.encryptAndDrain(bytes) }
        }

        /// Sends `length` octets of the open file `file` from `offset`, holding the outbound direction
        /// for the WHOLE transfer rather than for each chunk.
        ///
        /// Without this, the connection inherits ``TransportConnection``'s copying default, whose
        /// ``TransportConnection/send(_:)`` call sits inside the chunk loop — so under this backbone's
        /// exclusion the lease is taken and released once per 64 KiB chunk, and a sender arriving in
        /// the gap between two chunks writes its octets into the MIDDLE of a body the peer is reading
        /// against a `Content-Length` it already has (RFC 9112 §6.2). The record stream stays
        /// well-formed while that happens, which is what makes it dangerous: TLS accepts the splice
        /// and the damage lands one layer up, in the HTTP framing, unseen. This override takes the
        /// exclusion once and drives the ungated ``encryptAndDrain(_:)``; the copies are identical,
        /// the framing is not. `pread` (not `read`) so the caller's descriptor offset is never
        /// disturbed, and the loop never buffers more than one chunk regardless of file size.
        ///
        /// Standards: pread() per POSIX.1-2017 (IEEE Std 1003.1-2017); TLS 1.3 per RFC 8446 §5.1.
        func sendFile(descriptor file: Int32, offset: Int, length: Int) async throws {
            guard length > 0 else {
                return
            }
            try await sendPump.withExclusiveAccess {
                try await self.preadAndEncrypt(file, offset: offset, length: length)
            }
        }

        /// The `pread` chunk loop of ``sendFile(descriptor:offset:length:)``.
        ///
        /// The caller holds ``sendPump`` for every iteration, which is the entire point of the
        /// override; it fails closed if the file delivers fewer than `length` octets, because the
        /// caller has already framed that length and a silent short body would desync the connection.
        private func preadAndEncrypt(_ file: Int32, offset: Int, length: Int) async throws {
            var remaining = length
            var cursor = offset
            var chunk = [UInt8](repeating: 0, count: min(Self.fileChunkOctets, length))
            while remaining > 0 {
                let count = Self.preadChunk(file, &chunk, min(chunk.count, remaining), cursor)
                guard count > 0 else {
                    throw TransportError.ioFailed(
                        count == 0
                            ? "sendFile: file ended \(remaining) octet(s) short of the framed length"
                            : "sendFile: pread errno \(errno)"
                    )
                }
                try await encryptAndDrain(Array(chunk[..<count]))
                cursor += count
                remaining -= count
            }
        }

        /// One `pread(2)` of `wanted` octets into `chunk` at `cursor`, retrying `EINTR`; `-1` on
        /// failure.
        private static func preadChunk(
            _ file: Int32,
            _ chunk: inout [UInt8],
            _ wanted: Int,
            _ cursor: Int
        ) -> Int {
            chunk.withUnsafeMutableBytes { raw -> Int in
                while true {
                    // SE-0458 (ADR 0009): unsafe by the pointer parameter. `raw` is this call's own
                    // buffer, valid for at least `wanted` octets (`wanted <= chunk.count`), and does
                    // not escape.
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

        /// The `SSL_write` loop of ``send(_:)`` and of ``sendFile(descriptor:offset:length:)``.
        ///
        /// The caller holds ``sendPump``, and ``assertOutboundLeased()`` is what makes that a checked
        /// claim rather than a comment: this is the sole encrypt core, so a gated entry point refactored
        /// into an ungated one — which is exactly how the per-chunk splice above arrived — is caught
        /// here, before the first `SSL_write` puts a record into the write BIO.
        private func encryptAndDrain(_ bytes: [UInt8]) async throws {
            assertOutboundLeased("a TLS encrypt")
            var offset = 0
            while offset < bytes.count {
                let outcome = engine.withLock { $0.encrypt(bytes, from: offset) }
                switch outcome {
                    case .produced(let written):
                        offset += written
                        try await drainCiphertext()  // push this record out before the next
                    case .wantWrite:
                        try await drainCiphertext()
                    case .wantRead:
                        // TLS 1.2 renegotiation only; unreachable on the TLS 1.3 default (RFC 8446
                        // §4.6.3 removed renegotiation). It parks on READABILITY while holding the
                        // send exclusion, which BoringSSL's committed-write contract requires and
                        // which no other sender can shortcut.
                        try await drainCiphertext()
                        _ = try await fillCiphertext()
                    case .closedByPeer:
                        throw TransportError.ioFailed("SSL_write error \(SSL_ERROR_ZERO_RETURN)")
                    case .transportEnded:
                        throw TransportError.ioFailed("SSL_write error \(SSL_ERROR_SYSCALL)")
                    case .failed(let status):
                        throw TransportError.ioFailed("SSL_write error \(status)")
                }
            }
            try await drainCiphertext()
        }

        // MARK: - Close

        func close() async {
            closeDescriptor()
        }

        /// Closes the descriptor synchronously to unblock a parked read/write (audit CC4) — the server's
        /// once-per-connection cancellation handler calls this; it is the idempotent ``closeDescriptor()``.
        func cancel() {
            closeDescriptor()
        }

        private func closeDescriptor() {
            guard !isClosed.exchange(true, ordering: .acquiringAndReleasing) else {
                return
            }
            // Close the fd on the loop (deregisters interest + resumes any parked waiter so an in-flight
            // receive/send unblocks). The `SSL`/BIOs are freed at `deinit`, once the loop has released the
            // handler closures that retain `self`.
            eventLoop.closeDescriptor(descriptor)
        }

        // MARK: - Ciphertext pump (raw socket ↔ memory BIOs)

        /// Drains all ciphertext `SSL` has queued to the socket, under ``sendPump``.
        ///
        /// The exclusion is skipped entirely when nothing is owed, which is the common case on the read
        /// path: a receive only reaches here to clear records a renegotiation produced. When something
        /// *is* owed the wait is real, and bounded by the peer draining its TCP receive window.
        private func flushCiphertext() async throws {
            let owed = engine.withLock { $0.hasUnsentCiphertext() }
            guard owed else {
                return
            }
            try await sendPump.withExclusiveAccess { try await self.drainCiphertext() }
        }

        /// The ungated core of ``flushCiphertext()`` — the caller MUST already hold ``sendPump``.
        ///
        /// Split out because ``AsyncExclusion`` is not reentrant (CWE-833): ``send(_:)`` holds the
        /// exclusion for its whole body and calls this directly, where taking it again would deadlock.
        /// The `precondition` is the point of the split — the discipline is checked on every ordinary
        /// send rather than described in a comment that cannot fail.
        ///
        /// The close-flag guard keeps a pump resumed after ``cancel()``/``close()`` from touching the
        /// descriptor *number*, which the kernel may already have reused for another connection.
        private func drainCiphertext() async throws {
            assertOutboundLeased("the TLS ciphertext drain")
            while true {
                guard !isClosed.load(ordering: .acquiring) else {
                    throw TransportError.closed
                }
                do {
                    guard try engine.withLock({ try $0.pumpOutbound(to: descriptor) }) else {
                        return
                    }
                }
                catch is PortableTLSEngine.WouldBlock {
                    try await awaitWritable()
                }
            }
        }

        /// Reads one batch of ciphertext from the socket into the read BIO for `SSL_read` to decrypt,
        /// awaiting readability on `EAGAIN`.
        ///
        /// Returns `false` at socket EOF. Nothing is held across the park: the `read(2)` and the
        /// `BIO_write` that follows it are one critical section inside the engine, and a park happens
        /// only when the `read(2)` produced nothing at all. The close-flag guard mirrors
        /// ``drainCiphertext()``: never touch a since-closed (possibly reused) descriptor number.
        private func fillCiphertext() async throws -> Bool {
            while true {
                guard !isClosed.load(ordering: .acquiring) else {
                    throw TransportError.closed
                }
                do {
                    return try engine.withLock { try $0.ingestCiphertext(from: descriptor) }
                }
                catch is PortableTLSEngine.WouldBlock {
                    try await awaitReadable()
                }
            }
        }

        // MARK: - Readiness (one-shot, on the loop)

        /// Awaits socket readability for the ciphertext pump.
        ///
        /// Honors per-park task cancellation (the ``TransportConnection`` receive contract): the
        /// handler tears the connection down (``cancel()``), the loop's close sweep resumes this
        /// continuation, and the check below surfaces `CancellationError` before the pump can touch
        /// the closed descriptor — whose *number* the kernel may already have reused. A refused
        /// registration (the descriptor died before this park) fails the waiter immediately for the
        /// same reason. These parks sit behind `WANT_READ`/`WANT_WRITE`, off the decrypt hot path, so
        /// the handler cost is irrelevant (audit CC4 concerned the data-ready path).
        private func awaitReadable() async throws {
            try await withTaskCancellationHandler {
                try await withUnsafeThrowingContinuation {
                    (continuation: UnsafeContinuation<Void, any Error>) in
                    let once = OnceResumer(continuation)
                    let registered = eventLoop.waitReadable(descriptor) {
                        once.resume(returning: ())
                    }
                    if !registered {
                        once.resume(throwing: TransportError.closed)
                    }
                }
            } onCancel: {
                self.cancel()
            }
            try Task.checkCancellation()
        }

        /// Awaits socket writability for the ciphertext pump — see ``awaitReadable()`` on cancellation.
        private func awaitWritable() async throws {
            try await withTaskCancellationHandler {
                try await withUnsafeThrowingContinuation {
                    (continuation: UnsafeContinuation<Void, any Error>) in
                    let once = OnceResumer(continuation)
                    let registered = eventLoop.waitWritable(descriptor) {
                        once.resume(returning: ())
                    }
                    if !registered {
                        once.resume(throwing: TransportError.closed)
                    }
                }
            } onCancel: {
                self.cancel()
            }
            try Task.checkCancellation()
        }
    }

#endif
