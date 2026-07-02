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
//  readiness loop — `SSL_ERROR_WANT_READ`/`WANT_WRITE` become "await more socket bytes / flush". The
//  serve task is pinned to the loop (``preferredTaskExecutor``), so handshake, decrypt, encrypt and the
//  raw socket I/O all run inline on the loop thread with no hop and no thread-per-connection.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` (the opt-in `HTTP_PORTABLE_TLS` build).
//
//  Standards: TLS 1.3 (RFC 8446) + ALPN (RFC 7301) over a POSIX.1-2017 TCP (RFC 9293) socket; readiness
//  via BSD kqueue / Linux epoll.
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
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
    /// `SSL`/BIO access is confined to the loop thread (the serve task is pinned and I/O is serial per
    /// connection), so the type is safe to share — `@unchecked Sendable`.
    final class PortableTLSConnection: TransportConnection, @unchecked Sendable {
        let id: TransportConnectionID
        let peer: TransportAddress
        let isSecure = true

        var negotiatedApplicationProtocol: String? { negotiated.withLock(\.self) }
        var tlsPeerSubject: String? { tlsPeerIdentity?.subject }
        var tlsPeerIdentity: TLSPeerIdentity? { peerIdentity.withLock(\.self) }

        /// The loop is a `TaskExecutor`; pinning the serve task to it runs decrypt → handler → encrypt
        /// inline on the loop thread (audit R4).
        var preferredTaskExecutor: (any TaskExecutor)? { eventLoop }

        private let ssl: OpaquePointer
        /// Ciphertext IN: raw socket bytes are `BIO_write`-fed here for `SSL_read` to decrypt.
        private let readBIO: UnsafeMutablePointer<BIO>
        /// Ciphertext OUT: `SSL_write`/handshake leave ciphertext here for us to drain to the socket.
        private let writeBIO: UnsafeMutablePointer<BIO>
        private let descriptor: Int32
        private let eventLoop: TLSEventLoop
        private let clientAuth: TransportTLS.ClientAuth
        private let verifyPeer: (@Sendable ([[UInt8]]) -> Bool)?
        private let isClosed = Atomic<Bool>(false)
        /// `true` once the `SSL` (and its BIOs) have been freed — once-only across ``deinit`` paths.
        private let freed = Mutex<Bool>(false)
        private let negotiated = Mutex<String?>(nil)
        /// The verified client-certificate identity (G3), captured once at handshake completion.
        private let peerIdentity = Mutex<TLSPeerIdentity?>(nil)
        /// Reused plaintext receive buffer (`SSL_read` decrypts into it) — audit P1.
        private let scratch = Mutex<[UInt8]>([])
        /// Reused ciphertext pump buffer (raw socket ↔ BIO), sized once.
        private let cipher = Mutex<[UInt8]>([UInt8](repeating: 0, count: 16_384))

        /// A non-blocking socket read/write reported it would block — await readiness and retry.
        private struct WouldBlock: Error {}

        init(
            id: TransportConnectionID,
            peer: TransportAddress,
            ssl: OpaquePointer,
            readBIO: UnsafeMutablePointer<BIO>,
            writeBIO: UnsafeMutablePointer<BIO>,
            descriptor: Int32,
            eventLoop: TLSEventLoop,
            clientAuth: TransportTLS.ClientAuth,
            verifyPeer: (@Sendable ([[UInt8]]) -> Bool)?
        ) {
            self.id = id
            self.peer = peer
            self.ssl = ssl
            self.readBIO = readBIO
            self.writeBIO = writeBIO
            self.descriptor = descriptor
            self.eventLoop = eventLoop
            self.clientAuth = clientAuth
            self.verifyPeer = verifyPeer
        }

        deinit {
            // Free the SSL (and, since `SSL_set_bio` transferred ownership, both memory BIOs) exactly
            // once. Safe on any thread: at deinit no reference remains, so nothing can race the free.
            let firstFree = freed.withLock { wasFreed -> Bool in
                defer { wasFreed = true }
                return !wasFreed
            }
            if firstFree {
                CHTTPBoringSSL_SSL_free(ssl)
            }
        }

        // MARK: - Handshake

        /// Drives the TLS handshake to completion through the memory BIOs, then captures the negotiated
        /// ALPN protocol and applies the client-auth (mutual TLS) trust policy — throwing on failure.
        func performHandshake() async throws {
            while true {
                // `SSL_accept` (not `SSL_do_handshake`) so the session enters server accept-state on the
                // first call; subsequent calls continue the handshake after each BIO pump.
                let result = CHTTPBoringSSL_SSL_accept(ssl)
                try await flushCiphertext()  // push any handshake records SSL produced
                if result == 1 {
                    break
                }
                let status = CHTTPBoringSSL_SSL_get_error(ssl, result)
                switch status {
                    case SSL_ERROR_WANT_READ:
                        guard try await fillCiphertext() else {
                            throw TransportError.tlsConfigurationFailed("handshake EOF")
                        }
                    case SSL_ERROR_WANT_WRITE:
                        try await awaitWritable()
                    default:
                        throw TransportError.tlsConfigurationFailed("SSL_accept error \(status)")
                }
            }

            negotiated.withLock { $0 = OpenSSLTLS.negotiatedApplicationProtocol(of: ssl) }
            // Client-auth (G3): the TLS layer is permissive (`permissive_verify` always accepts), so the
            // `verifyPeer` hook is the *sole* validator of a presented chain. RFC 8446 §4.4.2.4 requires a
            // presented certificate to be validated — so a nil hook (no validator) **fails closed**:
            // an unvalidated chain MUST NOT be trusted (audit F4). An absent chain is allowed under
            // `.optional`/`.none` and unreachable under `.required` (the handshake already failed).
            let chain = OpenSSLTLS.peerDERChain(of: ssl)
            let accepted =
                chain.isEmpty
                ? (clientAuth != .required)
                : (verifyPeer?(chain) ?? false)
            guard accepted else {
                throw TransportError.tlsConfigurationFailed(
                    "the client certificate was rejected by verifyPeer"
                )
            }
            if !chain.isEmpty {
                // The full verified identity (G3): DER chain + leaf subject + leaf SANs, captured
                // once here — off the byte path — and surfaced as request-scoped context.
                let identity = TLSPeerIdentity(
                    chainDER: chain, subject: OpenSSLTLS.peerSubject(of: ssl)
                )
                peerIdentity.withLock { $0 = identity }
            }
        }

        // MARK: - Receive

        /// Receives up to `maxLength` decrypted bytes, or `nil` once the peer closes (TLS close-notify).
        func receive(maxLength: Int) async throws -> [UInt8]? {
            let count = try await readPlaintext(maxLength: maxLength)
            guard count > 0 else {
                return nil
            }
            return scratch.withLock { Array($0[..<count]) }
        }

        /// Reads up to `maxLength` decrypted bytes into the reused scratch and appends them to `buffer`
        /// (audit P1), returning the count appended (`0` once the peer closes).
        func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
            let count = try await readPlaintext(maxLength: maxLength)
            if count > 0 {
                scratch.withLock { buffer.append(contentsOf: $0[..<count]) }
            }
            return count
        }

        /// `SSL_read` into the scratch, pumping ciphertext from the socket on `WANT_READ` — the shared
        /// decrypt loop.
        ///
        /// Returns the plaintext byte count, or `0` at end of stream. A read torn down by its own
        /// task's cancellation (the ``TransportConnection`` receive contract — see ``awaitReadable()``)
        /// surfaces as `CancellationError`.
        private func readPlaintext(maxLength: Int) async throws -> Int {
            do {
                return try await decryptLoop(maxLength: maxLength)
            }
            catch _ where Task.isCancelled {
                // The teardown — or a pre-cancelled task finding the descriptor already closed —
                // surfaces as a transport error; report the standard cancellation signal instead.
                throw CancellationError()
            }
        }

        /// The decrypt loop body of ``readPlaintext(maxLength:)``.
        private func decryptLoop(maxLength: Int) async throws -> Int {
            while true {
                let count = scratch.withLock { (b: inout [UInt8]) -> Int32 in
                    if b.count < maxLength {
                        b = [UInt8](repeating: 0, count: max(1, maxLength))
                    }
                    return b.withUnsafeMutableBytes { raw in
                        CHTTPBoringSSL_SSL_read(ssl, raw.baseAddress, Int32(maxLength))
                    }
                }
                if count > 0 {
                    return Int(count)
                }
                let status = CHTTPBoringSSL_SSL_get_error(ssl, count)
                switch status {
                    case SSL_ERROR_ZERO_RETURN:
                        return 0  // clean TLS close-notify
                    case SSL_ERROR_WANT_READ:
                        // A renegotiation may owe the peer records first.
                        try await flushCiphertext()
                        guard try await fillCiphertext() else {
                            return 0  // socket EOF before close-notify — treat as end of stream
                        }
                    case SSL_ERROR_WANT_WRITE:
                        try await awaitWritable()
                    case SSL_ERROR_SYSCALL:
                        return 0  // abrupt peer EOF with nothing queued
                    default:
                        throw TransportError.ioFailed("SSL_read error \(status)")
                }
            }
        }

        // MARK: - Send

        /// Encrypts and sends all of `bytes`, draining the produced ciphertext to the socket.
        func send(_ bytes: [UInt8]) async throws {
            guard !bytes.isEmpty else {
                return
            }
            var offset = 0
            while offset < bytes.count {
                // `SSL_write` synchronously (no `await` may span `withUnsafeBytes`); `bytes` is immutable,
                // so the pointer is stable across the loop's suspension points.
                let written = bytes.withUnsafeBytes { raw -> Int32 in
                    CHTTPBoringSSL_SSL_write(
                        ssl,
                        raw.baseAddress?.advanced(by: offset),
                        Int32(raw.count - offset)
                    )
                }
                if written > 0 {
                    offset += Int(written)
                    try await flushCiphertext()  // push this record out before the next
                    continue
                }
                let status = CHTTPBoringSSL_SSL_get_error(ssl, written)
                switch status {
                    case SSL_ERROR_WANT_WRITE:
                        try await flushCiphertext()
                    case SSL_ERROR_WANT_READ:
                        try await flushCiphertext()
                        _ = try await fillCiphertext()
                    default:
                        throw TransportError.ioFailed("SSL_write error \(status)")
                }
            }
            try await flushCiphertext()
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

        /// Drains all ciphertext `SSL` has queued in ``writeBIO`` to the socket, awaiting writability on
        /// a full send buffer.
        ///
        /// The close-flag guard keeps a pump resumed after ``cancel()``/``close()`` from touching the
        /// descriptor *number*, which the kernel may already have reused for another connection.
        private func flushCiphertext() async throws {
            while CHTTPBoringSSL_BIO_ctrl_pending(writeBIO) > 0 {
                guard !isClosed.load(ordering: .acquiring) else {
                    throw TransportError.closed
                }
                let chunk = cipher.withLock { (buffer: inout [UInt8]) -> Int in
                    Int(
                        buffer.withUnsafeMutableBytes { raw in
                            CHTTPBoringSSL_BIO_read(writeBIO, raw.baseAddress, Int32(raw.count))
                        }
                    )
                }
                guard chunk > 0 else {
                    return
                }
                var offset = 0
                while offset < chunk {
                    do {
                        offset += try cipher.withLock { (buffer: inout [UInt8]) -> Int in
                            try buffer.withUnsafeBytes { raw -> Int in
                                let slice = UnsafeRawBufferPointer(rebasing: raw[offset ..< chunk])
                                return try Self.writeOnce(descriptor, slice)
                            }
                        }
                    }
                    catch is WouldBlock {
                        try await awaitWritable()
                    }
                }
            }
        }

        /// Reads one batch of ciphertext from the socket into ``readBIO`` for `SSL_read` to decrypt,
        /// awaiting readability on `EAGAIN`.
        ///
        /// Returns `false` at socket EOF. The close-flag guard mirrors ``flushCiphertext()``: never
        /// touch a since-closed (possibly reused) descriptor number.
        private func fillCiphertext() async throws -> Bool {
            while true {
                guard !isClosed.load(ordering: .acquiring) else {
                    throw TransportError.closed
                }
                do {
                    let count = try cipher.withLock { (buffer: inout [UInt8]) -> Int in
                        try buffer.withUnsafeMutableBytes { raw in
                            try Self.readOnce(descriptor, raw.baseAddress, raw.count)
                        }
                    }
                    if count == 0 {
                        return false  // EOF
                    }
                    cipher.withLock { buffer in
                        _ = buffer.withUnsafeBytes { raw in
                            CHTTPBoringSSL_BIO_write(readBIO, raw.baseAddress, Int32(count))
                        }
                    }
                    return true
                }
                catch is WouldBlock {
                    try await awaitReadable()
                }
            }
        }

        /// One non-blocking `read`, retrying `EINTR`, mapping `EAGAIN`/`EWOULDBLOCK` to ``WouldBlock``.
        private static func readOnce(
            _ descriptor: Int32,
            _ base: UnsafeMutableRawPointer?,
            _ capacity: Int
        ) throws -> Int {
            while true {
                let count = read(descriptor, base, capacity)
                if count >= 0 {
                    return count
                }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { throw WouldBlock() }
                throw TransportError.ioFailed("read errno \(errno)")
            }
        }

        /// One non-blocking `write`/`send`, retrying `EINTR`, mapping `EAGAIN` to ``WouldBlock``.
        private static func writeOnce(
            _ descriptor: Int32,
            _ buffer: UnsafeRawBufferPointer
        ) throws -> Int {
            while true {
                let base = buffer.baseAddress
                let count = buffer.count
                // SO_NOSIGPIPE (Darwin) / MSG_NOSIGNAL (Linux) suppress SIGPIPE on a peer RST.
                #if canImport(Darwin)
                    let written = write(descriptor, base, count)
                #else
                    let written = send(descriptor, base, count, Int32(MSG_NOSIGNAL))
                #endif
                if written >= 0 {
                    return written
                }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { throw WouldBlock() }
                throw TransportError.ioFailed("write errno \(errno)")
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
