//
//  HTTPTLSEngine.swift
//  HTTPTransport
//
//  Phase 3d — ``PortableTLSEngine`` over the from-scratch `HTTPTLS` machine: the pure-Swift
//  replacement for the BoringSSL-calling half of the portable backbone, behind the SAME
//  method surface ``PortableTLSConnection``'s pumps drive. The file name carries the engine
//  (`HTTPTLS`); the TYPE name stays `PortableTLSEngine` because the two engine flavors are
//  build-exclusive (`HTTP_PORTABLE_TLS` vs the temporary `HTTP_BORINGSSL_TLS`) and the
//  connection compiles against exactly one.
//
//  The outcome mapping, old → new. libssl's WANT_* protocol reported what the LAST call
//  needs; the sans-I/O machine has no such states — it consumes what it is fed and queues
//  what it owes — so the analogues fall out of buffer arithmetic instead of `SSL_get_error`:
//
//  - `wantRead`  = "no plaintext/completion available AND no un-fed ciphertext buffered" —
//    feed ``ingestCiphertext(from:)`` and retry (exactly `SSL_ERROR_WANT_READ`'s pump step).
//  - `wantWrite` is NEVER produced: the machine's outbound queue cannot "fill" the way a
//    BIO's write path could; socket backpressure surfaces solely as ``WouldBlock`` from
//    ``pumpOutbound(to:)``, which is where the old engine's staging already parked. The
//    connection's `wantWrite` arms remain, now unreachable — deleted with the gate in 3e.
//  - `closedByPeer` = the machine's `.peerClosed` event / `connectionClosed` terminal state
//    (`SSL_ERROR_ZERO_RETURN`'s close_notify meaning, §6.1).
//  - `transportEnded` is the CONNECTION's to report (socket EOF in `fillCiphertext`); the
//    machine cannot observe a vanished transport, so this engine never returns it.
//  - `failed` = a funneled ``TLSHandshakeError``: the typed alert+reason evidence replaces
//    the BoringSSL error-queue drain (see ``TLSFailureEvidence``); the queued §6 alert is
//    collected into ``outbound`` FIRST, so the peer still receives what §6.2 owes it.
//
//  Same concurrency terms as the engine it replaces: reachable only through the `Mutex`
//  that owns it (one lock, both directions), `~Copyable` so the machine state cannot be
//  lifted past that lock. The machine itself is a value — nothing here shares mutable
//  state — but the type stays `@unchecked Sendable` solely to ride the `Mutex`.
//
//  Standards: TLS 1.3 (RFC 8446) — §5.1 sizes ``ciphertextWindow``; §4.6.1 tickets are
//  issued here (two, the BoringSSL default count) at handshake completion; §6.1
//  close_notify surfaces as ``Outcome/closedByPeer``.
//

#if HTTP_PORTABLE_TLS_SWIFT

    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import HTTPTLS

    /// The HTTPTLS session for one connection, with the buffers that move bytes in and out.
    // SAFETY: `@unchecked Sendable` on the usual Mutex-payload terms (the same terms the
    // BoringSSL flavor carried): the ONLY reference to a constructed engine is the
    // `Mutex<PortableTLSEngine>` inside `PortableTLSConnection`, `~Copyable` forbids lifting
    // a copy past that lock, and every stored property is a plain value (no shared mutable
    // state) — the annotation exists solely so the value may live inside the `Mutex`.
    struct PortableTLSEngine: ~Copyable, @unchecked Sendable {
        /// What one engine call did — the same classification vocabulary the pumps have
        /// always driven (see the file comment for the old → new mapping).
        enum Outcome {
            /// The call succeeded, moving `count` octets (or completing the handshake, as `1`).
            case produced(Int)
            /// More ciphertext is needed — feed ``ingestCiphertext(from:)`` and retry.
            case wantRead
            /// Unreachable on this engine (see the file comment); kept so the connection's
            /// pump switches compile identically against both flavors.
            case wantWrite
            /// The peer sent close_notify (RFC 8446 §6.1).
            case closedByPeer
            /// Unreachable on this engine — socket EOF is the connection's observation.
            case transportEnded
            /// A funneled ``TLSHandshakeError``, with the connection identity and the §6
            /// alert captured as ``TLSFailureEvidence``.
            case failed(TLSFailureEvidence)
        }

        /// A non-blocking socket read/write reported it would block — await readiness and retry.
        struct WouldBlock: Error {}

        /// The largest single TLS record on the wire: 2^14 octets of ciphertext plus the 256
        /// octets of expansion RFC 8446 §5.1 permits, over the 5-octet header of §5.2.
        static let ciphertextWindow = 16_384 + 256 + 5

        /// The status octet the old backbone's field reports spelled for a close_notify hit
        /// on the write path (`SSL_ERROR_ZERO_RETURN`) — kept for grep compatibility.
        static let peerClosedStatus = 6
        /// Its abrupt-EOF sibling (`SSL_ERROR_SYSCALL`) — same grep-compatibility terms.
        static let transportEndedStatus = 5

        /// How many §4.6.1 NewSessionTickets to issue at handshake completion — two, the
        /// count BoringSSL servers send by default, so real clients cache a spare.
        private static let sessionTicketCount = 2

        /// The sans-I/O TLS 1.3 machine (records in, events out).
        private var connection: TLSServerConnection
        /// The connection this engine serves — carried so a fatal outcome names WHOSE
        /// failure it is (``TLSFailureEvidence``); never read on the happy path.
        private let connectionID: TransportConnectionID
        /// Ciphertext read from the socket on its way into the machine — the adaptive
        /// scratch (ADD-P2), so an idle connection holds nothing beyond the floor.
        private var inbound = ReceiveScratch()
        /// Socket octets not yet fed to the machine.
        private var pendingCiphertext: [UInt8] = []
        /// Decrypted application octets not yet delivered to a receiver.
        private var plaintext: [UInt8] = []
        /// The delivered prefix of ``plaintext`` (compacted when fully drained).
        private var plaintextCursor = 0
        /// Ciphertext the machine owes the socket (compacted when fully drained).
        private var outbound: [UInt8] = []
        /// The already-written prefix of ``outbound``.
        private var outboundCursor = 0
        /// The completed handshake's outcome, captured at `.handshakeCompleted`.
        private var negotiated: TLSNegotiatedParameters?
        /// Set once the peer's close_notify arrived (§6.1).
        private var peerClosed = false
        /// The first fatal classification — repeated on every later call, like a poisoned
        /// `SSL` re-reporting its error.
        private var failure: TLSFailureEvidence?

        init(connection: consuming TLSServerConnection, connectionID: TransportConnectionID) {
            self.connection = connection
            self.connectionID = connectionID
        }

        deinit {
            // ARC owns everything; ``release()`` exists for surface parity with the
            // BoringSSL flavor and is a no-op here.
        }

        // MARK: - Residency oracles

        /// Octets the plaintext delivery buffer holds resident.
        func plaintextResidentBytes() -> Int { plaintext.capacity }

        /// Octets the ciphertext pump buffers hold resident.
        func ciphertextResidentBytes() -> Int {
            inbound.residentBytes + pendingCiphertext.capacity + outbound.capacity
        }

        // MARK: - Handshake

        /// One handshake step: feeds buffered ciphertext through the machine.
        /// `.produced(1)` means the handshake completed (and §4.6.1 tickets were queued).
        mutating func acceptHandshake() -> Outcome {
            guard negotiated == nil else {
                return .produced(1)
            }
            if let failure {
                return .failed(failure)
            }
            guard !pendingCiphertext.isEmpty else {
                return .wantRead
            }
            do {
                try absorb(events: connection.receiveSynchronously(takePendingCiphertext()))
            }
            catch {
                return fail(error, in: "SSL_accept")
            }
            guard negotiated != nil else {
                return peerClosed ? .closedByPeer : .wantRead
            }
            issueSessionTickets()
            return .produced(1)
        }

        /// The ALPN protocol the completed handshake selected (RFC 7301).
        func negotiatedProtocol() -> String? { negotiated?.alpnProtocol }

        /// The peer's certificate chain, leaf first, in DER (§4.4.2) — signature-verified
        /// by the machine before the handshake completed.
        func peerChainDER() -> [[UInt8]] { negotiated?.clientCertificateChainDER ?? [] }

        /// The peer leaf certificate's subject Common Name.
        func peerSubject() -> String? {
            negotiated?.clientCertificateChainDER.first.flatMap(X509SubjectCommonName.extract)
        }

        // MARK: - Plaintext

        /// Delivers up to `ceiling` decrypted octets into `sink`, feeding buffered
        /// ciphertext through the machine when the delivery buffer runs dry.
        ///
        /// Decrypt and copy-out are ONE call under the engine's lock (audit F-02's
        /// invariant, structural here: nothing exposes the delivery buffer).
        mutating func decrypt(ceiling: Int, into sink: inout [UInt8]) -> Outcome {
            if let count = deliverPlaintext(ceiling: ceiling, into: &sink) {
                return .produced(count)
            }
            if peerClosed {
                return .closedByPeer
            }
            if let failure {
                return .failed(failure)
            }
            guard !pendingCiphertext.isEmpty else {
                return .wantRead
            }
            do {
                try absorb(events: connection.receiveSynchronously(takePendingCiphertext()))
            }
            catch {
                return fail(error, in: "SSL_read")
            }
            if let count = deliverPlaintext(ceiling: ceiling, into: &sink) {
                return .produced(count)
            }
            return peerClosed ? .closedByPeer : .wantRead
        }

        /// Queues `bytes` from `offset` as protected application data.
        ///
        /// The §5.2 records land in ``outbound`` for the pump. Whole-buffer, always: the
        /// machine commits everything it is given, so a partial `produced` never happens on
        /// this engine.
        mutating func encrypt(_ bytes: [UInt8], from offset: Int) -> Outcome {
            do {
                try connection.send(
                    applicationData: offset == 0 ? bytes : Array(bytes[offset...])
                )
            }
            catch {
                if case .connectionClosed = error {
                    return .closedByPeer  // our §6.1 write side is done — ZERO_RETURN's arm
                }
                return fail(error, in: "SSL_write")
            }
            collectOutbound()
            return .produced(bytes.count - offset)
        }

        // MARK: - Ciphertext pump

        /// Whether any ciphertext is still owed to the socket.
        func hasUnsentCiphertext() -> Bool { outboundCursor < outbound.count }

        /// Advances the outbound pump by one bounded `write(2)`, returning `false` once
        /// nothing is owed.
        ///
        /// Throws ``WouldBlock`` with the cursor intact when the send buffer is full, so the
        /// caller awaits writability and calls again — octets are never lost or re-sent.
        mutating func pumpOutbound(to descriptor: Int32) throws -> Bool {
            guard outboundCursor < outbound.count else {
                compactOutbound()
                return false
            }
            let upper = min(outbound.count, outboundCursor + Self.ciphertextWindow)
            // SE-0458 (ADR 0009): unsafe by the pointer parameter. The range is this type's
            // own cursor into storage it appended in the same acquisition; nothing escapes.
            let written = try outbound.withUnsafeBytes { raw in
                try unsafe Self.writeOnce(
                    descriptor,
                    UnsafeRawBufferPointer(rebasing: raw[outboundCursor ..< upper])
                )
            }
            outboundCursor += written
            return true
        }

        /// Reads one batch of ciphertext from the socket into the feed queue, returning
        /// `false` at socket EOF.
        mutating func ingestCiphertext(from descriptor: Int32) throws -> Bool {
            // SE-0458 (ADR 0009): unsafe by the closure's pointer parameter — the window is
            // sized by ``ReceiveScratch`` immediately before the call and does not escape.
            let count = try unsafe inbound.read(ceiling: Self.ciphertextWindow) { raw in
                try unsafe Self.readOnce(descriptor, raw.baseAddress, raw.count)
            }
            guard count > 0 else {
                return false  // EOF
            }
            pendingCiphertext.append(contentsOf: inbound.received(count))
            return true
        }

        // MARK: - Teardown

        /// Surface parity with the BoringSSL flavor — ARC owns this engine's state.
        mutating func release() {
            // Nothing to free: the machine, its keys, and the buffers are plain values.
        }

        // MARK: - Internals

        /// Takes the whole feed queue (keeping its capacity for the next socket read).
        private mutating func takePendingCiphertext() -> [UInt8] {
            let feed = pendingCiphertext
            pendingCiphertext.removeAll(keepingCapacity: true)
            return feed
        }

        /// Routes machine events into the engine's buffers and flags, then collects any
        /// outbound records the feed produced.
        private mutating func absorb(events: [TLSServerEvent]) {
            for event in events {
                switch event {
                    case .handshakeCompleted(let parameters):
                        negotiated = parameters
                    case .applicationData(let octets):
                        plaintext.append(contentsOf: octets)
                    case .peerClosed:
                        peerClosed = true
                }
            }
            collectOutbound()
        }

        /// Copies up to `ceiling` undelivered plaintext octets into `sink`; nil when empty.
        private mutating func deliverPlaintext(
            ceiling: Int, into sink: inout [UInt8]
        ) -> Int? {
            let available = plaintext.count - plaintextCursor
            guard available > 0 else {
                return nil
            }
            let count = min(available, max(1, ceiling))
            sink.append(contentsOf: plaintext[plaintextCursor ..< plaintextCursor + count])
            plaintextCursor += count
            if plaintextCursor == plaintext.count {
                plaintext.removeAll(keepingCapacity: true)
                plaintextCursor = 0
            }
            return count
        }

        /// Drains the machine's outbound queue into the pump buffer.
        private mutating func collectOutbound() {
            let produced = connection.outboundBytes()
            guard !produced.isEmpty else {
                return
            }
            if outbound.isEmpty {
                outbound = produced  // adopt, no copy — the common whole-flight case
            }
            else {
                outbound.append(contentsOf: produced)
            }
        }

        /// Resets the outbound buffer once fully written (capacity kept — same shape as the
        /// old engine's staging buffer, which never shrank either).
        private mutating func compactOutbound() {
            guard !outbound.isEmpty else {
                return
            }
            outbound.removeAll(keepingCapacity: true)
            outboundCursor = 0
        }

        /// §4.6.1: queues the post-handshake NewSessionTickets.
        ///
        /// Only when the intake configured a vault. A ticket failure costs the tickets,
        /// never the connection — the machine's own contract — so the throw is discarded.
        private mutating func issueSessionTickets() {
            for _ in 0 ..< Self.sessionTicketCount {
                guard (try? connection.issueSessionTicket()) != nil else {
                    break  // no vault (or a vault fault): resumption is simply not offered
                }
            }
            collectOutbound()
        }

        /// The one fatal funnel: the §6 alert the machine queued is collected FIRST (so the
        /// peer still receives it), then the typed evidence is pinned and repeated forever.
        private mutating func fail(
            _ error: TLSHandshakeError, in call: StaticString
        ) -> Outcome {
            collectOutbound()  // the funneled alert is already queued — get it to the wire
            if error == .connectionClosed, peerClosed {
                return .closedByPeer  // octets after the peer's close_notify — not a fault
            }
            let evidence = TLSFailureEvidence(
                call: call, connectionID: connectionID, error: error
            )
            failure = evidence
            return .failed(evidence)
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
