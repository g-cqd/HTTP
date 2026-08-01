//
//  PortableTLSEngine.swift
//  HTTPTransport
//
//  The `SSL` object, its two memory BIOs, and the three buffers that feed them — behind ONE lock.
//
//  BoringSSL's own header settles how much concurrency is allowed, and the answer is none.
//  `include/openssl/ssl.h`, opening the "SSL connections" section:
//
//      An |SSL| object represents a single TLS or DTLS connection. Although the shared |SSL_CTX| is
//      thread-safe, an |SSL| is not thread-safe and may only be used on one thread at a time.
//
//  There is no reader/writer split to exploit: `SSL_read` and `SSL_write` are not "one of each is
//  fine", they are two uses of the same non-thread-safe object, and a memory BIO is a plain growable
//  buffer with no locking of its own. So the correct shape is one lock over the whole engine, not a
//  read lock and a write lock — and this type makes that structural. The pointers are `private`, every
//  `SSL_*`/`BIO_*` call in the transport is a method here, and the value is reachable only through the
//  `Mutex` that owns it (``PortableTLSConnection``). CWE-663: the API is non-reentrant, so the
//  encapsulation is the enforcement.
//
//  Two consequences are baked into the method shapes rather than left to callers:
//
//  - `SSL_get_error` classifies the *last* operation by reading per-`SSL` state, so it is paired with
//    its call inside one acquisition and the caller only ever sees an ``Outcome``. Splitting the pair
//    would let another task's `SSL_*` call rewrite the classification in between.
//  - The outbound pump's staging range lives *with* the staging buffer (``staged``), so a count read
//    under one acquisition can never be used to slice the buffer under another (CWE-362, TOCTOU).
//
//  Standards: TLS 1.3 (RFC 8446) — §5.1 caps a record's ciphertext at 2^14 + 256 octets over a
//  5-octet header, which is where ``ciphertextWindow`` comes from; §6.1 is the close_notify that
//  surfaces as ``Outcome/closedByPeer``.
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif

    /// The libssl session for one connection, with the buffers that move bytes in and out of it.
    ///
    /// `@unchecked Sendable` on the usual `Mutex`-payload terms, and no more than that: the only way
    /// to reach one is through the `Mutex` that owns it, which is what supplies BoringSSL's "one
    /// thread at a time". `~Copyable` so the value cannot be lifted out of `withLock` — a copy would
    /// carry the same `SSL` pointer past the lock that guards it.
    struct PortableTLSEngine: ~Copyable, @unchecked Sendable {
        /// What one `SSL_*` call did, classified by the `SSL_get_error` taken in the same breath.
        enum Outcome {
            /// The call succeeded, moving `count` octets (or completing the handshake, as `1`).
            case produced(Int)
            /// `SSL_ERROR_WANT_READ` — feed ``ingestCiphertext(from:)`` and retry.
            case wantRead
            /// `SSL_ERROR_WANT_WRITE` — drain with ``pumpOutbound(to:)`` and retry.
            case wantWrite
            /// `SSL_ERROR_ZERO_RETURN` — the peer sent close_notify (RFC 8446 §6.1).
            case closedByPeer
            /// `SSL_ERROR_SYSCALL` — the transport ended with nothing queued; an abrupt peer EOF.
            case transportEnded
            /// Any other `SSL_get_error` status, carried verbatim for the caller's message.
            case failed(Int32)
        }

        /// A non-blocking socket read/write reported it would block — await readiness and retry.
        struct WouldBlock: Error {}

        /// The largest single TLS record on the wire: 2^14 octets of ciphertext plus the 256 octets of
        /// expansion RFC 8446 §5.1 permits, over the 5-octet record header of §5.2.
        ///
        /// A ceiling, not an allocation: both ciphertext buffers below grow toward it only when a peer
        /// shows it needs the room.
        static let ciphertextWindow = 16_384 + 256 + 5

        private let ssl: OpaquePointer
        /// Ciphertext IN: raw socket bytes are `BIO_write`-fed here for `SSL_read` to decrypt.
        private let readBIO: UnsafeMutablePointer<BIO>
        /// Ciphertext OUT: `SSL_write`/handshake leave ciphertext here for us to drain to the socket.
        private let writeBIO: UnsafeMutablePointer<BIO>

        /// Decrypted bytes `SSL_read` produces, sized to what this peer sends (ADD-P2).
        private var plaintext = ReceiveScratch()
        /// Ciphertext read from the socket on its way into ``readBIO`` — the same adaptive shape, so a
        /// connection that never reads holds nothing and an ordinary one holds the 2 KiB floor.
        private var inbound = ReceiveScratch()
        /// Ciphertext staged out of ``writeBIO`` on its way to the socket.
        ///
        /// Materialized by the first flush and grown to what a record actually needs, never to the
        /// ceiling up front.
        private var outbound: [UInt8] = []
        /// The sub-range of ``outbound`` that is staged and not yet on the wire.
        ///
        /// It lives here, beside the buffer, precisely so no caller can hold a stale bound across a
        /// lock boundary — the defect this type was extracted to remove.
        private var staged = 0 ..< 0
        /// `true` once ``release()`` has freed the `SSL`; no method is valid afterwards.
        private var isReleased = false

        init(
            ssl: OpaquePointer,
            readBIO: UnsafeMutablePointer<BIO>,
            writeBIO: UnsafeMutablePointer<BIO>
        ) {
            self.ssl = ssl
            self.readBIO = readBIO
            self.writeBIO = writeBIO
        }

        deinit {
            // Ownership of the `SSL` is the connection's: it calls `release()` from its own `deinit`,
            // once, so this value never frees anything on its own.
        }

        // MARK: - Residency oracles

        /// Octets the plaintext receive scratch holds resident (ADD-P2's oracle).
        func plaintextResidentBytes() -> Int { plaintext.residentBytes }

        /// Octets both ciphertext pump buffers hold resident.
        func ciphertextResidentBytes() -> Int { inbound.residentBytes + outbound.count }

        // MARK: - Handshake

        /// One `SSL_accept` step. `.produced(1)` means the handshake completed.
        ///
        /// `SSL_accept` rather than `SSL_do_handshake` so the session enters server accept-state on the
        /// first call; later calls continue the handshake after each BIO pump.
        mutating func acceptHandshake() -> Outcome {
            let result = CHTTPBoringSSL_SSL_accept(ssl)
            guard result != 1 else {
                return .produced(1)
            }
            return classify(result)
        }

        /// The ALPN protocol the completed handshake selected (RFC 7301).
        func negotiatedProtocol() -> String? { OpenSSLTLS.negotiatedApplicationProtocol(of: ssl) }

        /// The peer's certificate chain, leaf first, in DER.
        func peerChainDER() -> [[UInt8]] { OpenSSLTLS.peerDERChain(of: ssl) }

        /// The peer leaf certificate's subject.
        func peerSubject() -> String? { OpenSSLTLS.peerSubject(of: ssl) }

        // MARK: - Plaintext

        /// One `SSL_read` into the adaptive plaintext scratch, delivering what it produced to `sink`.
        ///
        /// Decrypt and copy-out are ONE acquisition, and the produced count never leaves this method
        /// as a bound anyone could re-use (audit F-02). The previous shape returned the count and let
        /// the caller re-enter for the bytes; between those two acquisitions a second receiver could
        /// `SSL_read` over the same scratch, so the first caller copied out the second's plaintext —
        /// one byte duplicated into one caller and lost from the other. That is CWE-362 (a race on a
        /// shared resource) over CWE-367 (the classic TOCTOU: check the count, then use it), and it is
        /// the same defect ``staged`` was introduced to remove from the outbound pump. It is not
        /// spelled out of the callers here, it is unspellable: the bytes are already in `sink` when
        /// this returns and nothing exposes the scratch.
        ///
        /// `sink` is appended to only on ``Outcome/produced(_:)``, so a retry outcome — or a caller
        /// that abandons the loop on cancellation — leaves it exactly as it was.
        mutating func decrypt(ceiling: Int, into sink: inout [UInt8]) -> Outcome {
            // `max(1, …)`: `SSL_read` with a zero-length buffer is not a read, it is an error report.
            // The window is `raw.count`, never `ceiling` (ADD-P2), and `clamping` because `SSL_read`
            // takes an `int` — a window past `Int32.max` would trap the conversion, where a shorter
            // read is always legal.
            // SE-0458 (ADR 0009): the call is unsafe by the closure's pointer parameter. The buffer is
            // sized by ``ReceiveScratch`` immediately before the call, is valid for exactly `raw.count`
            // octets, and does not escape this closure.
            let count = unsafe plaintext.read(ceiling: max(1, ceiling)) { raw in
                let room = Int32(clamping: raw.count)
                return unsafe Int(CHTTPBoringSSL_SSL_read(ssl, raw.baseAddress, room))
            }
            guard count <= 0 else {
                // `sink` is the caller's accumulator, never this engine's storage, so the append
                // cannot alias `plaintext` — and it happens here, under the acquisition that produced
                // the octets, which is the entire point of the parameter.
                sink.append(contentsOf: plaintext.received(count))
                return .produced(count)
            }
            return classify(Int32(clamping: count))
        }

        /// One `SSL_write` of `bytes` from `offset`.
        ///
        /// The pointer must be the same on every retry of a call that did not complete: BoringSSL's
        /// `SSL_write` contract is that "a failed |SSL_write| still commits to the data passed in […]
        /// retries will fail if they also do not reuse the same |buf| pointer" (`ssl.h`), enforced by
        /// the `SSL_R_BAD_WRITE_RETRY` check in `s3_pkt.cc`. `bytes` is an immutable `Array`, so
        /// `withUnsafeBytes` yields the same base address every time — and the connection's send
        /// exclusion is what stops a *different* caller's buffer from arriving in between.
        func encrypt(_ bytes: [UInt8], from offset: Int) -> Outcome {
            // SE-0458 (ADR 0009): unsafe by the closure's pointer parameter; the pointer is used only
            // for the duration of the call and does not escape.
            let written = bytes.withUnsafeBytes { raw -> Int32 in
                unsafe CHTTPBoringSSL_SSL_write(
                    ssl,
                    raw.baseAddress?.advanced(by: offset),
                    Int32(clamping: raw.count - offset)
                )
            }
            guard written <= 0 else {
                return .produced(Int(written))
            }
            return classify(written)
        }

        // MARK: - Ciphertext pump

        /// Whether any ciphertext is still owed to the socket, staged or queued in ``writeBIO``.
        func hasUnsentCiphertext() -> Bool {
            !staged.isEmpty || CHTTPBoringSSL_BIO_ctrl_pending(writeBIO) > 0
        }

        /// Advances the outbound pump by one step, returning `false` once nothing is owed.
        ///
        /// Stages from ``writeBIO`` when nothing is staged, then writes what the socket will take.
        ///
        /// Throws ``WouldBlock`` with the staging intact when the send buffer is full, so the caller
        /// awaits writability and calls again — the staged range is never lost and never re-read.
        mutating func pumpOutbound(to descriptor: Int32) throws -> Bool {
            if staged.isEmpty {
                stage()
                guard !staged.isEmpty else {
                    return false
                }
            }
            // SE-0458 (ADR 0009): unsafe by the pointer parameters. `staged` is a range this type set
            // from a `BIO_read` count into storage it sized in the same acquisition, so the rebase is
            // always in bounds; the pointer does not escape.
            let written = try outbound.withUnsafeBytes { raw in
                try unsafe Self.writeOnce(
                    descriptor,
                    UnsafeRawBufferPointer(rebasing: raw[staged])
                )
            }
            staged = staged.lowerBound + written ..< staged.upperBound
            return true
        }

        /// Reads one batch of ciphertext into ``readBIO``, returning `false` at socket EOF.
        ///
        /// The `read(2)` and the `BIO_write` are one critical section on purpose: split them and two
        /// pumps could read in order and then feed ``readBIO`` out of order, which is the same record
        /// corruption as an interleaved flush, just inbound.
        mutating func ingestCiphertext(from descriptor: Int32) throws -> Bool {
            // SE-0458 (ADR 0009): unsafe by the closure's pointer parameter — the window is sized by
            // ``ReceiveScratch`` immediately before the call and does not escape it.
            let count = try unsafe inbound.read(ceiling: Self.ciphertextWindow) { raw in
                try unsafe Self.readOnce(descriptor, raw.baseAddress, raw.count)
            }
            guard count > 0 else {
                return false  // EOF
            }
            // SE-0458 (ADR 0009): the slice is the octets the read above just produced.
            let produced = Int32(clamping: count)
            inbound.received(count)
                .withUnsafeBytes { raw in
                    _ = unsafe CHTTPBoringSSL_BIO_write(readBIO, raw.baseAddress, produced)
                }
            return true
        }

        // MARK: - Teardown

        /// Frees the `SSL` — and, since `SSL_set_bio` transferred ownership, both memory BIOs.
        ///
        /// Idempotent, and terminal: no other method is valid afterwards.
        mutating func release() {
            guard !isReleased else {
                return
            }
            isReleased = true
            CHTTPBoringSSL_SSL_free(ssl)
        }

        // MARK: - Internals

        /// Moves the next batch of ciphertext out of ``writeBIO`` into ``outbound``.
        ///
        /// The buffer is materialized here rather than at construction and grows only toward
        /// ``ciphertextWindow``: a connection that never sends holds no staging buffer at all, and one
        /// that sends a small response holds a small one (CWE-400 — idle residency set by demonstrated
        /// need, not by the worst case).
        private mutating func stage() {
            let pending = CHTTPBoringSSL_BIO_ctrl_pending(writeBIO)
            guard pending > 0 else {
                return
            }
            let want = min(pending, Self.ciphertextWindow)
            if outbound.count < want {
                outbound = [UInt8](repeating: 0, count: want)
            }
            // SE-0458 (ADR 0009): unsafe by the closure's pointer parameter; `BIO_read` writes at most
            // `raw.count` octets into storage sized on the line above, and nothing escapes.
            let moved = outbound.withUnsafeMutableBytes { raw in
                unsafe Int(
                    CHTTPBoringSSL_BIO_read(writeBIO, raw.baseAddress, Int32(clamping: raw.count))
                )
            }
            staged = 0 ..< max(0, moved)
        }

        /// Classifies a non-positive `SSL_*` result through `SSL_get_error`.
        ///
        /// Called in the same acquisition as the operation it describes: `SSL_get_error` reports on the
        /// *last* operation this `SSL` performed, so a second task's call in between would rewrite the
        /// answer.
        private func classify(_ result: Int32) -> Outcome {
            switch CHTTPBoringSSL_SSL_get_error(ssl, result) {
                case SSL_ERROR_WANT_READ:
                    .wantRead
                case SSL_ERROR_WANT_WRITE:
                    .wantWrite
                case SSL_ERROR_ZERO_RETURN:
                    .closedByPeer
                case SSL_ERROR_SYSCALL:
                    .transportEnded
                case let status:
                    .failed(status)
            }
        }

        /// One non-blocking `read`, retrying `EINTR`, mapping `EAGAIN`/`EWOULDBLOCK` to ``WouldBlock``.
        private static func readOnce(
            _ descriptor: Int32,
            _ base: UnsafeMutableRawPointer?,
            _ capacity: Int
        ) throws -> Int {
            while true {
                let count = unsafe read(descriptor, base, capacity)
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
                    let written = unsafe write(descriptor, base, count)
                #else
                    let written = unsafe Glibc.send(descriptor, base, count, Int32(MSG_NOSIGNAL))
                #endif
                if written >= 0 {
                    return written
                }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { throw WouldBlock() }
                throw TransportError.ioFailed("write errno \(errno)")
            }
        }
    }

#endif
