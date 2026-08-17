//
//  HandshakeTestClient.swift
//  HTTPTLSTests
//
//  A minimal TLS 1.3 CLIENT built from the module's own primitives (record layer, key
//  schedule, transcript, coalescer) — the peer every non-trace end-to-end test drives the
//  server with. Deliberately composable rather than automatic: tests assemble the second
//  flight from building blocks (`certificateMessage`, `certificateVerifyMessage`,
//  `finishedMessage`) so the negative battery can produce PRECISELY wrong flights (bad
//  verify_data, wrong context string, wrong transcript) that no honest client API would emit.
//  X25519 + TLS_AES_128_GCM_SHA256 only — one suite exercises every machine path.
//

import Crypto

@testable internal import HTTPTLS

/// A scriptable TLS 1.3 client for exercising ``TLSServerConnection`` end to end.
struct HandshakeTestClient {
    /// The client's record layer (roles mirrored: its write is the server's read).
    var record = TLSRecordLayer()
    /// Handshake-message reassembly for the server's flights.
    var coalescer = TLSHandshakeCoalescer(maximumMessageLength: 1 << 17)
    /// The §4.4.1 transcript, client side.
    var transcript = TLSTranscriptHash(.sha256)
    /// The §7.1 ladder, client side.
    var schedule = TLSKeySchedule(hash: .sha256)
    /// The client's X25519 ephemeral.
    let privateKey = Curve25519.KeyAgreement.PrivateKey()
    /// The hello knobs (share is filled in by ``helloRecord(configure:)``).
    var hello = TestClientHello()
    /// `client_handshake_traffic_secret` (held for the client Finished).
    var clientHandshakeSecret: SymmetricKey?
    /// `server_handshake_traffic_secret` (held to check the server Finished).
    var serverHandshakeSecret: SymmetricKey?
    /// `client_application_traffic_secret_0` (installed after the client Finished).
    var clientApplicationSecret: SymmetricKey?
    /// An optional resumption offer: (ticket identity, PSK) — binder computed automatically.
    var preSharedKey: (identity: [UInt8], key: SymmetricKey)?
    /// Handshake messages received from the server, in order.
    var serverMessages: [TLSHandshakeCoalescer.Message] = []
    /// Application data received from the server.
    var applicationData: [[UInt8]] = []
    /// Alerts received from the server.
    var alerts: [TLSAlert] = []

    /// Builds the ClientHello record, drives the §7.1 early secret, and (when resuming)
    /// computes the real §4.2.11.2 binder.
    mutating func helloRecord(
        configure: ((inout TestClientHello) -> Void)? = nil
    ) throws -> [UInt8] {
        hello.keyShares = [(0x001D, [UInt8](privateKey.publicKey.rawRepresentation))]
        configure?(&hello)
        try schedule.deriveEarlySecret(preSharedKey: preSharedKey?.key)
        if let preSharedKey {
            hello.preSharedKey = (
                identities: [(preSharedKey.identity, 0)],
                binders: [[UInt8](repeating: 0, count: 32)]
            )
            var message = hello.message()
            let binder = try computeBinder(overTruncated: message)
            message.replaceSubrange((message.count - 32)..., with: binder)
            transcript.append(message)
            return TestClientHello.plaintextRecord(message)
        }
        let message = hello.message()
        transcript.append(message)
        return TestClientHello.plaintextRecord(message)
    }

    /// §4.2.11.2: the binder over `Truncate(ClientHello)` — everything before the binders
    /// list (one 32-octet binder ⇒ the last 2 + 33 octets are truncated away).
    private func computeBinder(overTruncated message: [UInt8]) throws -> [UInt8] {
        var truncated = TLSTranscriptHash(.sha256)
        truncated.append([UInt8](message[..<(message.count - 35)]))
        let binderKey = try schedule.binderKey(external: false)
        return schedule.finishedVerifyData(
            trafficSecret: binderKey, transcriptHash: truncated.currentHash
        )
    }

    /// Absorbs server octets, expecting whole records per call.
    ///
    /// Deframes record by record (the ServerHello's events must install keys before the
    /// flight record is deprotected), reassembles, follows the §7 key choreography, and
    /// collects messages/data/alerts.
    @discardableResult
    mutating func absorb(_ bytes: [UInt8]) throws -> [TLSHandshakeCoalescer.Message] {
        var fresh: [TLSHandshakeCoalescer.Message] = []
        var cursor = bytes.startIndex
        while cursor < bytes.endIndex {
            let bodyLength = Int(bytes[cursor + 3]) << 8 | Int(bytes[cursor + 4])
            let end = cursor + 5 + bodyLength
            try absorbRecord(bytes[cursor ..< end], into: &fresh)
            cursor = end
        }
        return fresh
    }

    /// Absorbs exactly one record's events.
    private mutating func absorbRecord(
        _ slice: ArraySlice<UInt8>, into fresh: inout [TLSHandshakeCoalescer.Message]
    ) throws {
        for event in try record.receive(slice) {
            switch event {
                case .handshake(let fragment):
                    coalescer.feed(fragment)
                    while let message = try coalescer.next() {
                        try track(message)
                        fresh.append(message)
                        serverMessages.append(message)
                    }
                case .applicationData(let content):
                    applicationData.append(content)
                case .alert(let alert):
                    alerts.append(alert)
            }
        }
    }

    /// The client-side §7 choreography per received message.
    private mutating func track(_ message: TLSHandshakeCoalescer.Message) throws {
        switch message.type {
            case .serverHello:
                transcript.append(message.raw)
                try deriveHandshakeKeys(serverHello: message)
            case .finished:
                try verifyServerFinished(message)
                transcript.append(message.raw)
                try deriveApplicationKeys()
            case .newSessionTicket, .keyUpdate:
                if message.type == .keyUpdate {
                    try record.ratchetReadKeys()  // §4.6.3: the server switched
                }
            default:
                transcript.append(message.raw)  // EE / CR / Certificate / CertificateVerify
        }
    }

    /// §7.1 after ServerHello: shared secret, handshake traffic secrets, both directions' keys.
    private mutating func deriveHandshakeKeys(
        serverHello: TLSHandshakeCoalescer.Message
    ) throws {
        var reader = TLSHandshakeReader(serverHello.body)
        _ = try reader.u16("version")
        _ = try reader.slice(32, "random")
        _ = try reader.vector8("echo")
        _ = try reader.u16("suite")
        _ = try reader.byte("compression")
        var extensions = TLSHandshakeReader(try reader.vector16("extensions"))
        var serverShare: [UInt8] = []
        while !extensions.isAtEnd {
            let type = try extensions.u16("type")
            let data = try extensions.vector16("data")
            guard type == TLSExtensionType.keyShare.rawValue else {
                continue
            }
            var share = TLSHandshakeReader(data)
            _ = try share.u16("group")
            serverShare = [UInt8](try share.vector16("key_exchange"))
        }
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverShare)
        try schedule.deriveHandshakeSecret(
            sharedSecret: privateKey.sharedSecretFromKeyAgreement(with: peer)
        )
        let helloHash = transcript.currentHash
        let clientSecret = try schedule.clientHandshakeTrafficSecret(transcriptHash: helloHash)
        let serverSecret = try schedule.serverHandshakeTrafficSecret(transcriptHash: helloHash)
        try record.installWriteKeys(suite: .aes128GcmSha256, trafficSecret: clientSecret)
        try record.installReadKeys(suite: .aes128GcmSha256, trafficSecret: serverSecret)
        clientHandshakeSecret = clientSecret
        serverHandshakeSecret = serverSecret
    }

    /// §4.4.4: checks the server Finished against the running transcript.
    private func verifyServerFinished(_ message: TLSHandshakeCoalescer.Message) throws {
        guard let serverHandshakeSecret else {
            throw TLSHandshakeError.internalError("Finished before ServerHello")
        }
        let expected = schedule.finishedVerifyData(
            trafficSecret: serverHandshakeSecret, transcriptHash: transcript.currentHash
        )
        guard expected == [UInt8](message.body) else {
            throw TLSHandshakeError.invalidFinished
        }
    }

    /// §7.1 after the server Finished: application secrets; server-side READ keys install now.
    private mutating func deriveApplicationKeys() throws {
        try schedule.deriveMasterSecret()
        let finishedHash = transcript.currentHash
        clientApplicationSecret = try schedule.clientApplicationTrafficSecret(
            transcriptHash: finishedHash
        )
        let serverSecret = try schedule.serverApplicationTrafficSecret(
            transcriptHash: finishedHash
        )
        try record.installReadKeys(suite: .aes128GcmSha256, trafficSecret: serverSecret)
    }

    // MARK: second-flight building blocks (composable so tests can corrupt precisely)

    /// A client Certificate message for `chain` (empty context, no entry extensions).
    func certificateMessage(chain: [[UInt8]]) -> [UInt8] {
        TLSCertificateCodec.certificate(chainDER: chain)
    }

    /// A client CertificateVerify over the CURRENT transcript with a real P-256 signature.
    func certificateVerifyMessage(
        signingKey: P256.Signing.PrivateKey,
        context: String = TLSCertificateVerify.clientContext
    ) throws -> [UInt8] {
        let content = TLSCertificateVerify.signedContent(
            context: context, transcriptHash: transcript.currentHash
        )
        let signature = try signingKey.signature(for: content)
        return TLSCertificateVerify(
            scheme: .ecdsaSecp256r1Sha256, signature: [UInt8](signature.derRepresentation)
        )
        .encoded()
    }

    /// The client Finished over the CURRENT transcript (optionally corrupted).
    func finishedMessage(corrupted: Bool = false) throws -> [UInt8] {
        guard let clientHandshakeSecret else {
            throw TLSHandshakeError.internalError("Finished before keys")
        }
        var verify = schedule.finishedVerifyData(
            trafficSecret: clientHandshakeSecret, transcriptHash: transcript.currentHash
        )
        if corrupted {
            verify[0] ^= 0x80
        }
        return TLSFinishedCodec.finished(verifyData: verify)
    }

    /// Sends handshake messages (appending each to the transcript first), then promotes the
    /// write direction to the application keys when `promote` — the client's flight end.
    mutating func sendFlight(
        _ messages: [[UInt8]], promote: Bool = true
    ) throws -> [UInt8] {
        var flight: [UInt8] = []
        for message in messages {
            transcript.append(message)
            flight += message
        }
        try record.send(handshake: flight)
        if promote, let clientApplicationSecret {
            try record.installWriteKeys(
                suite: .aes128GcmSha256, trafficSecret: clientApplicationSecret
            )
        }
        return record.outboundBytes()
    }

    /// The complete default second flight: just Finished.
    mutating func finishHandshake() throws -> [UInt8] {
        try sendFlight([try finishedMessage()])
    }

    /// Seals application data under the current write keys.
    mutating func applicationDataRecord(_ payload: [UInt8]) throws -> [UInt8] {
        try record.send(applicationData: payload)
        return record.outboundBytes()
    }

    /// A KeyUpdate under the current write keys, ratcheting the client write direction after.
    mutating func keyUpdateRecord(requesting: Bool) throws -> [UInt8] {
        try record.send(
            handshake: (requesting
                ? TLSKeyUpdateMessage.updateRequested : .updateNotRequested)
                .encoded()
        )
        try record.ratchetWriteKeys()
        return record.outboundBytes()
    }

    /// A `close_notify` under the current write keys.
    mutating func closeNotifyRecord() throws -> [UInt8] {
        try record.send(
            alert: TLSAlert(level: TLSAlert.warningLevel, description: .closeNotify)
        )
        return record.outboundBytes()
    }
}
