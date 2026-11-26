//
//  TLSClientConnection.swift
//  HTTPTLS
//
//  RFC 8446 §4 / §A.1 — the sans-I/O TLS 1.3 CLIENT connection, symmetrical to
//  ``TLSServerConnection``: octets in (`receive`), typed ``TLSClientEvent``s out, outbound
//  octets drained (`outboundBytes`). Validates the server's X.509 certificate chain and SAN
//  hostname via ``TLSX509ChainValidator`` (swift-certificates RFC 5280 + RFC 6125), verifies
//  the server's `CertificateVerify` signature (§4.4.3) and `Finished` HMAC (§4.4.4) before
//  releasing any application keys, and emits the client's `Finished` flight.
//

public import Crypto

/// A sans-I/O TLS 1.3 client connection (RFC 8446): records in, events out, one exit funnel.
public struct TLSClientConnection: Sendable {
    let configuration: TLSClientConfiguration
    let chainValidator: TLSX509ChainValidator
    var record = TLSRecordLayer()
    var coalescer: TLSHandshakeCoalescer
    var clientHello1Raw: [UInt8] = []
    var transcript: TLSTranscriptHash?
    var schedule: TLSKeySchedule?

    /// Current client handshake state (§A.1).
    public internal(set) var state: TLSClientHandshakeState = .idle
    /// Negotiated handshake parameters once `.connected`.
    public internal(set) var negotiated: TLSNegotiatedParameters?

    var clientRandom: [UInt8] = []
    var sessionID: [UInt8] = []
    var activeGroup: TLSNamedGroup = .x25519
    var activePrivateKey: [UInt8] = []
    var selectedSuite: TLSCipherSuite?
    var selectedAlpn: String?
    var peerRecordSizeLimit: Int?
    var usedHelloRetry = false
    var serverRequestedClientCertificate = false
    var serverCertificateChain: [[UInt8]] = []
    var serverHandshakeSecret: SymmetricKey?
    var clientHandshakeSecret: SymmetricKey?
    var sentCompatibilityCCS = false
    var sentCloseNotify = false
    var keyUpdates = TLSKeyUpdateState()
    var deframer = TLSRecordDeframer()

    /// Creates a TLS 1.3 client connection, validating `configuration.trustRootsDER` upfront.
    public init(
        configuration: TLSClientConfiguration
    ) throws(TLSX509ChainValidator.ConfigurationError) {
        try self.init(
            configuration: configuration,
            anchors: TLSTrustAnchors(rootsDER: configuration.trustRootsDER)
        )
    }

    /// Creates a TLS 1.3 client connection pinned to a shared, pre-decoded anchor set
    /// (`configuration.trustRootsDER` is ignored).
    public init(configuration: TLSClientConfiguration, anchors: TLSTrustAnchors) {
        self.configuration = configuration
        self.chainValidator = TLSX509ChainValidator(
            anchors: anchors,
            expectedHostname: configuration.serverName
        )
        self.coalescer = TLSHandshakeCoalescer(
            maximumMessageLength: configuration.maxHandshakeMessageLength
        )
    }

    /// Emits `ClientHello` into the outbound buffer and transitions `.idle` → `.expectingServerHello`.
    public mutating func start() throws(TLSHandshakeError) {
        guard state == .idle else {
            throw .unexpectedMessage(.clientHello)
        }
        guard let initialGroup = configuration.groups.first,
            !configuration.cipherSuites.isEmpty,
            !configuration.signatureSchemes.isEmpty
        else {
            throw .negotiationFailed("empty client configuration")
        }
        clientRandom = configuration.entropy.serverRandom()
        sessionID =
            configuration.middleboxCompatibilityMode
            ? configuration.entropy.serverRandom() : []
        activeGroup = initialGroup
        activePrivateKey = configuration.entropy.ephemeralPrivateKey(for: initialGroup)
        let hello = try clientHello(cookie: nil)
        clientHello1Raw = hello
        try emit(handshake: hello)
        state = .expectingServerHello
    }

    /// Drains every queued outbound wire record.
    public mutating func outboundBytes() -> [UInt8] {
        record.outboundBytes()
    }

    /// Feeds inbound wire octets from the peer and returns any connection-visible events.
    public mutating func receive(
        _ bytes: [UInt8]
    ) async throws(TLSHandshakeError) -> [TLSClientEvent] {
        guard state != .closed, state != .idle else {
            throw .connectionClosed
        }
        var events: [TLSClientEvent] = []
        var cursor = bytes.startIndex
        do {
            while let recordEvents = try deframer.pump(bytes, cursor: &cursor, through: &record) {
                for event in recordEvents {
                    try await handle(event, into: &events)
                }
            }
            return events
        }
        catch {
            throw fail(error)
        }
    }

    /// Encrypts and queues outbound application data (only valid once `.connected`).
    public mutating func send(applicationData bytes: [UInt8]) throws(TLSHandshakeError) {
        guard state == .connected else {
            throw .connectionClosed
        }
        do {
            try maintainKeyUpdates()
            try emitApplicationData(bytes)
        }
        catch {
            throw fail(error)
        }
    }

    private mutating func emitApplicationData(_ bytes: [UInt8]) throws(TLSHandshakeError) {
        do {
            try record.send(applicationData: bytes)
        }
        catch {
            throw .record(error)
        }
    }

    /// Queues a `close_notify` alert (§6.1) and transitions to `.closed`.
    public mutating func close() {
        guard !sentCloseNotify, state != .closed else {
            state = .closed
            return
        }
        sentCloseNotify = true
        state = .closed
        try? record.send(alert: TLSAlert(level: TLSAlert.warningLevel, description: .closeNotify))
    }

    mutating func fail(_ error: TLSHandshakeError) -> TLSHandshakeError {
        if state != .closed, let alert = error.alertDescription {
            try? record.send(alert: TLSAlert(level: 2, description: alert))
        }
        state = .closed
        return error
    }

    mutating func emit(handshake bytes: [UInt8]) throws(TLSHandshakeError) {
        do {
            try record.send(handshake: bytes)
        }
        catch {
            throw .record(error)
        }
    }

    static func sniHostname(_ candidate: String?) -> String? {
        guard let candidate, !candidate.isEmpty else {
            return nil
        }
        // RFC 6066 §3: literal IPv4/IPv6 addresses are forbidden in SNI.
        if candidate.contains(":") {
            return nil
        }
        let parts = candidate.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count == 4, parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }) {
            return nil
        }
        return candidate
    }
}
