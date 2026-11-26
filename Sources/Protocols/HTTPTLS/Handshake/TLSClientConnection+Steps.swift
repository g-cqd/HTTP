//
//  TLSClientConnection+Steps.swift
//  HTTPTLS
//
//  RFC 8446 §4.1.3 / §4.1.4 / §A.1 — record-event dispatch, the client message/state gate, and
//  ServerHello / HelloRetryRequest processing (handshake key derivation) for
//  ``TLSClientConnection``.
//

internal import Crypto

extension TLSClientConnection {
    mutating func handle(
        _ event: TLSRecordEvent, into events: inout [TLSClientEvent]
    ) async throws(TLSHandshakeError) {
        if case .handshake(let fragment) = event {
            coalescer.feed(fragment)
            try await drainHandshakeMessages(into: &events)
            return
        }
        let verdict = try TLSNonHandshakeRecord.classify(
            event,
            hasPartialHandshake: coalescer.hasPartialMessage,
            isConnected: state == .connected
        )
        if verdict == .peerClosed {
            state = .closed
        }
        if let surfaced = verdict.clientEvent {
            keyUpdates.consecutivePeerUpdates = 0
            events.append(surfaced)
        }
    }

    /// Runs every complete handshake message through the §A.1 gate.
    private mutating func drainHandshakeMessages(
        into events: inout [TLSClientEvent]
    ) async throws(TLSHandshakeError) {
        while let message = try coalescer.next() {
            guard state.accepts(message.type) else {
                throw .unexpectedMessage(message.type)
            }
            try await dispatch(message, into: &events)
        }
    }

    /// One arm per message type; ``TLSClientHandshakeState/accepts(_:)`` already admitted it.
    private mutating func dispatch(
        _ message: TLSHandshakeCoalescer.Message, into events: inout [TLSClientEvent]
    ) async throws(TLSHandshakeError) {
        switch message.type {
            case .serverHello:
                try processServerHello(message)
            case .encryptedExtensions:
                try processEncryptedExtensions(message)
            case .certificateRequest:
                try processCertificateRequest(message)
            case .certificate:
                try await processServerCertificate(message)
            case .certificateVerify:
                try processServerCertificateVerify(message)
            case .finished:
                try processServerFinished(message, into: &events)
            case .keyUpdate:
                let limit = configuration.maxConsecutivePeerKeyUpdates
                try keyUpdates.receive(message, limit: limit, record: &record)
            default:
                break  // NewSessionTicket: a stateless 1-RTT client accepts and does not store it
        }
    }

    private mutating func processServerHello(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        let hello = try TLSClientCodec.parseServerHello(message)
        try validateServerHello(hello)
        if transcript == nil {
            var running = TLSTranscriptHash(hello.cipherSuite.hash)
            running.append(clientHello1Raw)
            transcript = running
        }
        if hello.isHelloRetryRequest {
            try processHelloRetryRequest(hello, message: message)
            return
        }
        guard let group = hello.keyShareGroup, group == activeGroup,
            let serverShare = hello.keyShareExchange
        else {
            throw .illegalParameter("ServerHello key_share mismatch")
        }
        transcript?.append(message.raw)
        let shared = try TLSKeyExchange.sharedSecret(
            group: group,
            privateKey: activePrivateKey,
            peerShare: serverShare
        )
        try installHandshakeKeys(suite: hello.cipherSuite, sharedSecret: shared)
        state = .expectingEncryptedExtensions
    }

    private mutating func validateServerHello(
        _ hello: TLSClientCodec.ParsedServerHello
    ) throws(TLSHandshakeError) {
        guard hello.supportedVersion == 0x0304 else {
            throw .unsupportedVersion
        }
        guard hello.sessionID == sessionID else {
            throw .illegalParameter("ServerHello session_id_echo mismatch")
        }
        guard configuration.cipherSuites.contains(hello.cipherSuite) else {
            throw .illegalParameter("ServerHello cipher_suite not offered")
        }
        if let previous = selectedSuite, previous != hello.cipherSuite {
            throw .illegalParameter("ServerHello changed cipher_suite after HRR")
        }
        selectedSuite = hello.cipherSuite
    }

    /// §4.1.4: one HelloRetryRequest — collapse ClientHello1 into `message_hash`, re-key on the
    /// requested group, echo the cookie, and send ClientHello2.
    private mutating func processHelloRetryRequest(
        _ hello: TLSClientCodec.ParsedServerHello,
        message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        guard state == .expectingServerHello, !usedHelloRetry else {
            throw .unexpectedMessage(.serverHello)
        }
        usedHelloRetry = true
        guard let retryGroup = hello.keyShareGroup, configuration.groups.contains(retryGroup),
            retryGroup != activeGroup
        else {
            throw .illegalParameter("invalid HRR key_share group")
        }
        transcript?.collapseForHelloRetry()
        transcript?.append(message.raw)
        try sendCompatibilityCCSIfNeeded()
        activeGroup = retryGroup
        activePrivateKey = configuration.entropy.ephemeralPrivateKey(for: retryGroup)
        let retried = try clientHello(cookie: hello.cookie)
        transcript?.append(retried)
        try emit(handshake: retried)
        state = .expectingRetriedServerHello
    }

    /// Builds a ClientHello for the active group's key share (§4.1.2).
    func clientHello(cookie: [UInt8]?) throws(TLSHandshakeError) -> [UInt8] {
        let share = try TLSKeyExchange.publicShare(group: activeGroup, privateKey: activePrivateKey)
        return TLSClientCodec.clientHello(
            TLSClientCodec.HelloParameters(
                random: clientRandom,
                sessionID: sessionID,
                configuration: configuration,
                serverName: Self.sniHostname(configuration.serverName),
                keyShareGroup: activeGroup,
                keyShareExchange: share,
                cookie: cookie
            )
        )
    }

    /// Appendix D.4: one unprotected `change_cipher_spec` before the first protected record.
    mutating func sendCompatibilityCCSIfNeeded() throws(TLSHandshakeError) {
        guard configuration.middleboxCompatibilityMode, !sentCompatibilityCCS else {
            return
        }
        sentCompatibilityCCS = true
        do {
            try record.sendChangeCipherSpec()
        }
        catch {
            throw .record(error)
        }
    }

    /// §7.1: derives and installs the handshake traffic keys.
    private mutating func installHandshakeKeys(
        suite: TLSCipherSuite,
        sharedSecret: SharedSecret
    ) throws(TLSHandshakeError) {
        var ladder = TLSKeySchedule(hash: suite.hash)
        let transcriptHash = transcript?.currentHash ?? []
        do {
            try ladder.deriveEarlySecret()
            try ladder.deriveHandshakeSecret(sharedSecret: sharedSecret)
            clientHandshakeSecret = try ladder.clientHandshakeTrafficSecret(
                transcriptHash: transcriptHash
            )
            serverHandshakeSecret = try ladder.serverHandshakeTrafficSecret(
                transcriptHash: transcriptHash
            )
        }
        catch {
            throw .internalError("client handshake key schedule")
        }
        try sendCompatibilityCCSIfNeeded()
        guard let clientSecret = clientHandshakeSecret, let serverSecret = serverHandshakeSecret
        else {
            throw .internalError("client handshake secrets")
        }
        do {
            try record.installReadKeys(suite: suite, trafficSecret: serverSecret)
            try record.installWriteKeys(suite: suite, trafficSecret: clientSecret)
        }
        catch {
            throw .record(error)
        }
        schedule = ladder
    }
}
