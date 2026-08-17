//
//  TLSServerConnection+Flight.swift
//  HTTPTLS
//
//  RFC 8446 §4.1.3–§4.4.4 + §7 — the server's answer to an acceptable ClientHello, with the §7
//  key choreography exactly as the RFC 8448 traces stage it: ServerHello leaves unprotected;
//  the handshake traffic keys install (write, then read); EncryptedExtensions,
//  [CertificateRequest], [Certificate, CertificateVerify], Finished ride ONE handshake send
//  (so §5.1 coalescing matches the §3 trace record byte-exactly); the server's application
//  WRITE keys install right after its Finished; the application READ keys wait for the
//  client's Finished (+ClientFlight).
//

internal import Crypto

extension TLSServerConnection {
    /// Runs the full §4 server response: early secret → ServerHello → flight → app write keys.
    mutating func completeHandshakeFlight(
        _ hello: TLSClientHello,
        message: TLSHandshakeCoalescer.Message,
        suite: TLSCipherSuite,
        group: TLSNamedGroup,
        clientShare: TLSKeyShareEntry
    ) async throws(TLSHandshakeError) {
        var ladder = try establishEarlySecret(hello, message: message, suite: suite)
        // FAIL FAST, before any output: the signature-scheme intersection (§4.2.3/§9.2)
        // and the peer share's validity (§4.2.8.2) are both decidable now — a violation
        // must die as ONE plaintext alert, not a ServerHello followed by a sealed alert.
        let candidates = resumed ? [] : try selectSignatureSchemes(hello)
        let privateKey = configuration.entropy.ephemeralPrivateKey(for: group)
        let shared = try TLSKeyExchange.sharedSecret(
            group: group, privateKey: privateKey, peerShare: clientShare.keyExchange
        )
        var running = transcript ?? TLSTranscriptHash(suite.hash)
        running.append(message.raw)  // §4.4.1: the ClientHello enters the transcript
        let serverHandshakeSecret = try beginKeyExchange(
            hello,
            suite: suite,
            group: group,
            privateKey: privateKey,
            sharedSecret: shared,
            ladder: &ladder,
            running: &running
        )
        let flight = try await buildServerFlight(
            hello,
            ladder: ladder,
            running: &running,
            serverHandshakeSecret: serverHandshakeSecret,
            signatureSchemes: candidates
        )
        try emit(handshake: flight)  // one send — §5.1 coalescing, trace-exact
        try promoteToApplicationKeys(suite: suite, ladder: &ladder, running: running)
        transcript = running
        schedule = ladder
        selectedSuite = suite
        selectedGroup = group
        // §A.2: WAIT_CERT when we asked for a certificate, WAIT_FINISHED otherwise.
        state = clientAuthSchemes.isEmpty ? .expectingClientFinished : .expectingClientCertificate
    }

    /// §7.1's first Extract: the Early Secret, PSK-fed when a redeemable identity's binder
    /// verifies (§4.2.11.2 — fatal when it does not).
    private mutating func establishEarlySecret(
        _ hello: TLSClientHello,
        message: TLSHandshakeCoalescer.Message,
        suite: TLSCipherSuite
    ) throws(TLSHandshakeError) -> TLSKeySchedule {
        let selected = try selectPreSharedKey(hello, suite: suite)
        var ladder = TLSKeySchedule(hash: suite.hash)
        do {
            try ladder.deriveEarlySecret(preSharedKey: selected?.resumption.preSharedKey)
        }
        catch {
            throw .internalError("early secret stage")
        }
        if let selected, let offer = hello.preSharedKey {
            try verifyBinder(
                offer: offer,
                selected: selected,
                schedule: ladder,
                rawMessage: message.raw,
                priorTranscript: transcript
            )
            resumed = true
            selectedPskIdentity = UInt16(truncatingIfNeeded: selected.index)
        }
        return ladder
    }

    /// §4.1.3 + §7.4: ServerHello out (unprotected), the already-run ECDHE folded in,
    /// handshake traffic keys installed.
    private mutating func beginKeyExchange(
        _ hello: TLSClientHello,
        suite: TLSCipherSuite,
        group: TLSNamedGroup,
        privateKey: [UInt8],
        sharedSecret: SharedSecret,
        ladder: inout TLSKeySchedule,
        running: inout TLSTranscriptHash
    ) throws(TLSHandshakeError) -> SymmetricKey {
        let serverRandom = configuration.entropy.serverRandom()
        guard serverRandom.count == 32 else {
            throw .internalError("server random length")  // §4.1.3
        }
        let serverHello = TLSServerHelloEncoder.serverHello(
            random: serverRandom,
            sessionIDEcho: hello.legacySessionID,
            suite: suite,
            selectedIdentity: selectedPskIdentity,
            keyShareGroup: group,
            keyExchange: try TLSKeyExchange.publicShare(group: group, privateKey: privateKey)
        )
        running.append(serverHello)
        try emit(handshake: serverHello)  // plaintext epoch — §5.1
        emitCompatibilityCCSIfNeeded()  // D.4, before any write keys exist
        do {
            try ladder.deriveHandshakeSecret(sharedSecret: sharedSecret)
        }
        catch {
            throw .internalError("handshake secret stage")
        }
        let helloHash = running.currentHash  // Transcript-Hash(CH..SH), §7.1
        let clientSecret = try derive("c hs traffic") { () throws(TLSKeyScheduleError) in
            try ladder.clientHandshakeTrafficSecret(transcriptHash: helloHash)
        }
        let serverSecret = try derive("s hs traffic") { () throws(TLSKeyScheduleError) in
            try ladder.serverHandshakeTrafficSecret(transcriptHash: helloHash)
        }
        do {
            try record.installWriteKeys(suite: suite, trafficSecret: serverSecret)
            try record.installReadKeys(suite: suite, trafficSecret: clientSecret)
        }
        catch {
            throw .record(error)
        }
        clientHandshakeSecret = clientSecret
        if hello.offeredEarlyData {
            // §4.2.10 first option: the extension is never acknowledged; the client's early
            // records are skipped by trial deprotection within the configured budget.
            record.earlyDataSkipBudget = configuration.maxEarlyDataSkipOctets
        }
        return serverSecret
    }

    /// §4.3–§4.4: EncryptedExtensions ∥ [CertificateRequest] ∥ [Certificate ∥
    /// CertificateVerify] ∥ Finished, appended to the transcript as built.
    private mutating func buildServerFlight(
        _ hello: TLSClientHello,
        ladder: TLSKeySchedule,
        running: inout TLSTranscriptHash,
        serverHandshakeSecret: SymmetricKey,
        signatureSchemes: [TLSSignatureScheme]
    ) async throws(TLSHandshakeError) -> [UInt8] {
        var flight = TLSEncryptedExtensionsEncoder.encryptedExtensions(
            supportedGroupsHint: configuration.supportedGroupsHint,
            recordSizeLimit: hello.recordSizeLimit == nil ? nil : configuration.recordSizeLimit,
            acknowledgeServerName: hello.serverName != nil,
            alpnProtocol: selectedAlpn
        )
        running.append(flight)
        if !resumed, configuration.clientAuthentication.requestsCertificate {
            // §4.3.2 — and never alongside a PSK ("servers which are authenticating with a
            // PSK MUST NOT send a CertificateRequest in the main handshake", §2.2/§4.3.2).
            clientAuthSchemes = configuration.signatureSchemes.filter(
                \.isPermittedInCertificateVerify
            )
            let request = TLSCertificateRequestEncoder.certificateRequest(
                schemes: clientAuthSchemes
            )
            running.append(request)
            flight += request
        }
        if !resumed {
            flight += try await appendCertificateAndVerify(
                schemes: signatureSchemes, running: &running
            )
        }
        let finished = TLSFinishedCodec.finished(
            verifyData: ladder.finishedVerifyData(
                trafficSecret: serverHandshakeSecret, transcriptHash: running.currentHash
            )
        )
        running.append(finished)
        flight += finished
        return flight
    }

    /// §4.2.3/§9.2: the CertificateVerify scheme candidates — the client's offer ∩ the
    /// configuration, in server-preference order; checked BEFORE any output leaves.
    private func selectSignatureSchemes(
        _ hello: TLSClientHello
    ) throws(TLSHandshakeError) -> [TLSSignatureScheme] {
        guard let offered = hello.signatureAlgorithms, !offered.isEmpty else {
            throw .missingExtension(.signatureAlgorithms)  // §9.2: mandatory for cert auth
        }
        let candidates = configuration.signatureSchemes.filter {
            $0.isPermittedInCertificateVerify && offered.contains($0)
        }
        guard !candidates.isEmpty else {
            throw .negotiationFailed("signature schemes")  // §4.1.1
        }
        return candidates
    }

    /// §4.4.2/§4.4.3: the certificate chain and its transcript signature via the identity
    /// seam (`schemes` — the precomputed §4.2.3 candidates).
    private mutating func appendCertificateAndVerify(
        schemes candidates: [TLSSignatureScheme], running: inout TLSTranscriptHash
    ) async throws(TLSHandshakeError) -> [UInt8] {
        let chain = identity.certificateChainDER
        guard !chain.isEmpty else {
            throw .internalError("identity provided no certificate")  // §4.4.2 needs a leaf
        }
        let certificate = TLSCertificateCodec.certificate(chainDER: chain)
        running.append(certificate)
        let content = TLSCertificateVerify.signedContent(
            context: TLSCertificateVerify.serverContext,
            transcriptHash: running.currentHash  // §4.4.3: through Certificate
        )
        let signature: TLSSignature
        do {
            signature = try await identity.signature(over: content, algorithms: candidates)
        }
        catch {
            throw .signingFailed
        }
        guard candidates.contains(signature.scheme) else {
            throw .signingFailed  // the seam picked outside the offered list
        }
        let verify = TLSCertificateVerify(
            scheme: signature.scheme, signature: signature.bytes
        )
        .encoded()
        running.append(verify)
        return certificate + verify
    }

    /// §7.1's third stage after the server Finished: master secret, both application traffic
    /// secrets, the exporter — and the server's application WRITE keys (§7.2 staging; READ
    /// keys wait for the client Finished).
    private mutating func promoteToApplicationKeys(
        suite: TLSCipherSuite, ladder: inout TLSKeySchedule, running: TLSTranscriptHash
    ) throws(TLSHandshakeError) {
        do {
            try ladder.deriveMasterSecret()
        }
        catch {
            throw .internalError("master secret stage")
        }
        let finishedHash = running.currentHash  // Transcript-Hash(CH..server Finished)
        let serverSecret = try derive("s ap traffic") { () throws(TLSKeyScheduleError) in
            try ladder.serverApplicationTrafficSecret(transcriptHash: finishedHash)
        }
        clientApplicationSecret = try derive("c ap traffic") { () throws(TLSKeyScheduleError) in
            try ladder.clientApplicationTrafficSecret(transcriptHash: finishedHash)
        }
        exporterSecret = try derive("exp master") { () throws(TLSKeyScheduleError) in
            try ladder.exporterMasterSecret(transcriptHash: finishedHash)
        }
        do {
            try record.installWriteKeys(suite: suite, trafficSecret: serverSecret)
        }
        catch {
            throw .record(error)
        }
    }

    /// Bridges a §7.1 derivation's stage error into the funnel's currency.
    private func derive(
        _ label: String, _ derivation: () throws(TLSKeyScheduleError) -> SymmetricKey
    ) throws(TLSHandshakeError) -> SymmetricKey {
        do {
            return try derivation()
        }
        catch {
            throw .internalError("\(label) stage")
        }
    }
}
