//
//  TLSServerConnection.swift
//  HTTPTLS
//
//  RFC 8446 §4 — the sans-I/O TLS 1.3 SERVER connection: the handshake state machine (§A.2)
//  driving Phase 3a's record layer, transcript, and key schedule. Octets in (`receive`), typed
//  events out, outbound octets drained (`outboundBytes`) — the `HTTP2Connection` shape. All
//  cryptography is swift-crypto's; signing rides the ``TLSIdentityProvider`` seam.
//
//  The ONE exit funnel (the retirement-funnel lesson, relearned three times in this codebase):
//  every fatal path goes through ``fail(_:)`` — at most one alert queued, exactly one terminal
//  state, one typed error reported — and no path leaves keys half-installed, because keys only
//  move inside `process…` steps that either complete or funnel.
//
//  Inbound octets are split at §5.1 record boundaries HERE, and each record's events are
//  handled before the next record is deprotected: one feed can straddle a key installation
//  (ClientHello ∥ rejected early data, client Finished ∥ application data, KeyUpdate ∥ data
//  under the new keys), so batch-deprotecting a whole feed would open records with stale keys.
//
//  This file owns state, the funnel, and the splitter; ClientHello handling lives in
//  +ClientHello, the server flight in +Flight, PSK resumption in +Resumption, the client's
//  second flight in +ClientFlight, and §4.6 post-handshake traffic in +PostHandshake.
//

public import Crypto

/// A sans-I/O TLS 1.3 server connection (RFC 8446): records in, events out, one exit funnel.
public struct TLSServerConnection {
    /// The listener contract this connection negotiates under.
    let configuration: TLSServerConfiguration
    /// The certificate/signing identity (Phase 3c's seam).
    let identity: any TLSIdentityProvider
    /// The §5 record layer (Phase 3a).
    var record = TLSRecordLayer()
    /// §5.1 handshake-message reassembly.
    var coalescer: TLSHandshakeCoalescer
    /// The §4.4.1 running transcript (created once the suite fixes the hash).
    var transcript: TLSTranscriptHash?
    /// The §7.1 key-schedule ladder (created with the transcript).
    var schedule: TLSKeySchedule?
    /// The machine state (§A.2).
    public internal(set) var state: TLSServerHandshakeState = .expectingClientHello
    /// The completed handshake's outcome (nil until `.handshakeCompleted` fires).
    public internal(set) var negotiated: TLSNegotiatedParameters?

    // MARK: §7.1 secrets retained across flights

    /// `client_handshake_traffic_secret` — held to verify the client Finished (§4.4.4).
    var clientHandshakeSecret: SymmetricKey?
    /// `client_application_traffic_secret_0` — held until the client Finished installs it.
    var clientApplicationSecret: SymmetricKey?
    /// `resumption_master_secret` — feeds §4.6.1 tickets.
    var resumptionMaster: SymmetricKey?
    /// `exporter_master_secret` — feeds §7.5 exporters.
    var exporterSecret: SymmetricKey?

    // MARK: negotiation working state

    /// The selected suite (§4.1.1) — pinned by the first ClientHello, checked on retry.
    var selectedSuite: TLSCipherSuite?
    /// The selected key-exchange group (§4.2.8).
    var selectedGroup: TLSNamedGroup?
    /// The selected ALPN protocol (RFC 7301), when negotiated.
    var selectedAlpn: String?
    /// The client's SNI (RFC 6066), when offered.
    var clientServerName: String?
    /// The peer's RFC 8449 record-size limit, when negotiated.
    var peerRecordSizeLimit: Int?
    /// Whether the handshake resumed via PSK (§4.2.11).
    var resumed = false
    /// The §4.2.11 `selected_identity` echoed in the ServerHello, when resuming.
    var selectedPskIdentity: UInt16?
    /// Whether the one permitted HelloRetryRequest went out (§4.1.4).
    var sentHelloRetry = false
    /// The group the HelloRetryRequest demanded a share for (§4.2.8).
    var retryGroup: TLSNamedGroup?
    /// The §4.2.2 cookie the HelloRetryRequest carried, to be echoed exactly.
    var sentCookie: [UInt8]?
    /// Whether the D.4 compatibility CCS already went out (at most one).
    var sentCompatibilityCCS = false
    /// Whether our `close_notify` went out (§6.1 — each side sends exactly one).
    var sentCloseNotify = false
    /// The §4.2.3 schemes offered in our CertificateRequest (bounds the client's choice).
    var clientAuthSchemes: [TLSSignatureScheme] = []
    /// The client's presented chain, leaf first, DER (§4.4.2).
    var clientCertificateChain: [[UInt8]] = []
    /// The §4.6.1 `ticket_nonce` counter ("MUST be unique per ticket on this connection").
    var ticketNonceCounter: UInt64 = 0
    /// Whether a KeyUpdate with `update_requested` is outstanding (§4.6.3, from our side).
    var requestedPeerKeyUpdate = false
    /// Trailing partial-record octets awaiting the next feed (the splitter's buffer,
    /// capacity fixed at one max record — a length lie cannot grow it).
    var inboundHoldback: [UInt8] = []

    /// Creates a server connection for one accepted transport connection.
    public init(configuration: TLSServerConfiguration, identity: any TLSIdentityProvider) {
        self.configuration = configuration
        self.identity = identity
        coalescer = TLSHandshakeCoalescer(
            maximumMessageLength: configuration.maxHandshakeMessageLength
        )
        inboundHoldback.reserveCapacity(
            TLSRecordLimits.headerLength + TLSRecordLimits.maxCiphertextLength
        )
    }

    /// Feeds inbound wire octets; returns the events they complete.
    ///
    /// Any throw is fatal and already funneled: the alert (if owed) is queued for
    /// ``outboundBytes()`` and the state is terminal.
    public mutating func receive(
        _ bytes: [UInt8]
    ) async throws(TLSHandshakeError) -> [TLSServerEvent] {
        guard !state.isTerminal else {
            throw TLSHandshakeError.connectionClosed
        }
        var events: [TLSServerEvent] = []
        var cursor = bytes.startIndex
        do {
            while !state.isTerminal,
                let recordEvents = try pumpOneRecord(bytes, cursor: &cursor)
            {
                for event in recordEvents {
                    try await handle(event, into: &events)
                    if state.isTerminal {
                        break  // §6.1: octets after close_notify are ignored
                    }
                }
            }
            try maintainKeyUpdates()
        }
        catch {
            throw fail(error)
        }
        return events
    }

    /// The synchronous steady-state twin of ``receive(_:)`` for the post-ClientHello states.
    ///
    /// Every post-ClientHello message is processed without suspension (only the identity
    /// seam's signing is async), and the allocation oracle needs a synchronous body to
    /// measure. A ClientHello through this path is `unexpected_message`, which is the §4
    /// answer in every state this method is legal in.
    mutating func receiveConnected(
        _ bytes: [UInt8]
    ) throws(TLSHandshakeError) -> [TLSServerEvent] {
        guard !state.isTerminal else {
            throw TLSHandshakeError.connectionClosed
        }
        var events: [TLSServerEvent] = []
        var cursor = bytes.startIndex
        do {
            while !state.isTerminal,
                let recordEvents = try pumpOneRecord(bytes, cursor: &cursor)
            {
                for event in recordEvents {
                    try handleSynchronous(event, into: &events)
                    if state.isTerminal {
                        break
                    }
                }
            }
            try maintainKeyUpdates()
        }
        catch {
            throw fail(error)
        }
        return events
    }

    /// Drains every queued outbound wire octet.
    public mutating func outboundBytes() -> [UInt8] {
        record.outboundBytes()
    }

    /// Queues application data — legal from the server's Finished onward (§7.1 write epoch;
    /// data sent before the client Finished is 0.5-RTT, Appendix E.1.2's caveats apply).
    public mutating func send(applicationData bytes: [UInt8]) throws(TLSHandshakeError) {
        guard !state.isTerminal else {
            throw TLSHandshakeError.connectionClosed
        }
        do {
            try maintainKeyUpdates()
            try emitApplicationData(bytes)
        }
        catch {
            throw fail(error)
        }
    }

    /// Sends `close_notify` (§6.1) and closes the write direction — the graceful exit.
    ///
    /// Legal after the peer's own `close_notify` too (§6.1: "each party MUST send a
    /// close_notify ... before closing its write side"); a no-op once failed or already sent.
    public mutating func close() {
        if case .failed = state {
            return
        }
        if !sentCloseNotify {
            try? record.send(
                alert: TLSAlert(level: TLSAlert.warningLevel, description: .closeNotify)
            )
            sentCloseNotify = true
        }
        state = .closed
    }

    // MARK: the one exit funnel

    /// The single fatal exit: queues the owed §6 alert (at most once), pins the terminal
    /// state, and hands back the typed error for the caller's throw.
    ///
    /// Idempotent — a second failure cannot re-alert or overwrite the first.
    mutating func fail(_ error: TLSHandshakeError) -> TLSHandshakeError {
        guard !state.isTerminal else {
            return error
        }
        if let alert = error.alertDescription {
            try? record.send(alert: TLSAlert(level: TLSAlert.fatalLevel, description: alert))
        }
        state = .failed(error)
        return error
    }

    // MARK: the §5.1 record splitter

    /// Cuts exactly one record out of the feed (or the cross-feed holdback) and runs it
    /// through the record layer; nil when only a partial record remains (stashed).
    private mutating func pumpOneRecord(
        _ bytes: [UInt8], cursor: inout Int
    ) throws(TLSHandshakeError) -> [TLSRecordEvent]? {
        if inboundHoldback.isEmpty {
            guard cursor < bytes.endIndex else {
                return nil
            }
            let needed = recordLengthNeeded(bytes[cursor...])
            guard bytes.endIndex - cursor >= needed else {
                inboundHoldback.append(contentsOf: bytes[cursor...])
                cursor = bytes.endIndex
                return nil
            }
            let slice = bytes[cursor ..< cursor + needed]
            cursor += needed
            return try feedRecordLayer(slice)
        }
        topUpInboundHoldback(bytes, cursor: &cursor)  // header first, then the body
        let needed = recordLengthNeeded(inboundHoldback[...])
        guard inboundHoldback.count >= TLSRecordLimits.headerLength,
            inboundHoldback.count >= needed
        else {
            return nil
        }
        let events = try feedRecordLayer(inboundHoldback[..<needed])
        inboundHoldback.removeAll(keepingCapacity: true)
        return events
    }

    /// Tops the holdback up to the record header, re-derives the full length, then tops up
    /// to the whole record (never past it).
    private mutating func topUpInboundHoldback(_ bytes: [UInt8], cursor: inout Int) {
        for _ in 0 ..< 2 {  // once for the header, once for the body it reveals
            let needed = recordLengthNeeded(inboundHoldback[...])
            let take = min(needed - inboundHoldback.count, bytes.endIndex - cursor)
            guard take > 0 else {
                return
            }
            inboundHoldback.append(contentsOf: bytes[cursor ..< cursor + take])
            cursor += take
        }
    }

    /// How many octets the record at the slice's head occupies: the header alone until the
    /// length field is visible — or when the length lies past the §5.2 cap, in which case the
    /// bare header is fed and the record layer's own `validateHeader` raises the right error.
    private func recordLengthNeeded(_ bytes: ArraySlice<UInt8>) -> Int {
        let base = bytes.startIndex
        guard bytes.count >= TLSRecordLimits.headerLength else {
            return TLSRecordLimits.headerLength
        }
        let bodyLength = Int(bytes[base + 3]) << 8 | Int(bytes[base + 4])
        guard bodyLength <= TLSRecordLimits.maxCiphertextLength else {
            return TLSRecordLimits.headerLength  // fed bare; the layer throws record_overflow
        }
        return TLSRecordLimits.headerLength + bodyLength
    }

    /// Runs one record through the layer, converting its failures to the funnel's currency.
    private mutating func feedRecordLayer(
        _ slice: ArraySlice<UInt8>
    ) throws(TLSHandshakeError) -> [TLSRecordEvent] {
        do {
            return try record.receive(slice)
        }
        catch {
            throw .record(error)
        }
    }

    // MARK: record-event dispatch

    /// Routes one record event; §5.1's no-interleaving rule guards the non-handshake arms.
    private mutating func handle(
        _ event: TLSRecordEvent, into events: inout [TLSServerEvent]
    ) async throws(TLSHandshakeError) {
        switch event {
            case .handshake(let fragment):
                coalescer.feed(fragment)
                while let message = try coalescer.next() {
                    try await process(message, into: &events)
                    if state.isTerminal {
                        return
                    }
                }
            case .applicationData, .alert:
                try handleNonHandshake(event, into: &events)
        }
    }

    /// The synchronous dispatch twin (see ``receiveConnected(_:)``): identical semantics,
    /// with the ClientHello arm folded into `unexpected_message`.
    private mutating func handleSynchronous(
        _ event: TLSRecordEvent, into events: inout [TLSServerEvent]
    ) throws(TLSHandshakeError) {
        switch event {
            case .handshake(let fragment):
                coalescer.feed(fragment)
                while let message = try coalescer.next() {
                    try processSynchronous(message, into: &events)
                    if state.isTerminal {
                        return
                    }
                }
            case .applicationData, .alert:
                try handleNonHandshake(event, into: &events)
        }
    }

    /// The shared application-data/alert arms of both dispatchers.
    private mutating func handleNonHandshake(
        _ event: TLSRecordEvent, into events: inout [TLSServerEvent]
    ) throws(TLSHandshakeError) {
        switch event {
            case .handshake:
                throw .internalError("handshake event in the non-handshake dispatch")
            case .applicationData(let content):
                guard !coalescer.hasPartialMessage else {
                    throw .interleavedHandshake(.applicationData)  // §5.1
                }
                guard state == .connected else {
                    throw .record(.unexpectedProtectedRecord(.applicationData))
                }
                if !content.isEmpty {
                    events.append(.applicationData(content))  // empty = padding, dropped
                }
            case .alert(let alert):
                guard !coalescer.hasPartialMessage else {
                    throw .interleavedHandshake(.alert)  // §5.1
                }
                if alert.description == .closeNotify {
                    state = .closed
                    events.append(.peerClosed)
                }
                else if alert.description != .userCanceled {  // §6.1: user_canceled ignored
                    throw .peerAlert(alert)  // error alert — no answer owed (§6.2)
                }
        }
    }

    /// The §A.2 message/state gate: exactly one legal (state, type) pair per arm.
    private mutating func process(
        _ message: TLSHandshakeCoalescer.Message, into events: inout [TLSServerEvent]
    ) async throws(TLSHandshakeError) {
        switch (state, message.type) {
            case (.expectingClientHello, .clientHello),
                (.expectingRetriedClientHello, .clientHello):
                try await processClientHello(message)
            default:
                try processSynchronous(message, into: &events)
        }
    }

    /// The gate's synchronous arms — everything after the ClientHello.
    private mutating func processSynchronous(
        _ message: TLSHandshakeCoalescer.Message, into events: inout [TLSServerEvent]
    ) throws(TLSHandshakeError) {
        switch (state, message.type) {
            case (.expectingClientCertificate, .certificate):
                try processClientCertificate(message)
            case (.expectingClientCertificateVerify, .certificateVerify):
                try processClientCertificateVerify(message)
            case (.expectingClientFinished, .finished):
                try processClientFinished(message, into: &events)
            case (.connected, .keyUpdate):
                try processKeyUpdate(message)
            default:
                throw .unexpectedMessage(message.type)  // §4: wrong order is fatal
        }
    }

    // MARK: typed record-layer bridges

    /// Sends handshake content, converting record-layer failures to the funnel's currency.
    mutating func emit(handshake bytes: [UInt8]) throws(TLSHandshakeError) {
        do {
            try record.send(handshake: bytes)
        }
        catch {
            throw .record(error)
        }
    }

    /// Sends application data, converting record-layer failures.
    private mutating func emitApplicationData(_ bytes: [UInt8]) throws(TLSHandshakeError) {
        guard record.writeEpoch == .application else {
            throw .internalError("application data before the server Finished")
        }
        do {
            try record.send(applicationData: bytes)
        }
        catch {
            throw .record(error)
        }
    }
}
