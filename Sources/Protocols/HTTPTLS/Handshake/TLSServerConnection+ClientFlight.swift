//
//  TLSServerConnection+ClientFlight.swift
//  HTTPTLS
//
//  RFC 8446 §4.4 — the client's second flight: [Certificate ∥ CertificateVerify] ∥ Finished.
//  Client-auth semantics are the portable TLS backbone's, fail closed (its G3 audit):
//  `.required` + empty chain aborts (`certificate_required`, §4.4.2.4); `.optional` + empty
//  chain proceeds unauthenticated; a PRESENT chain is ALWAYS signature-verified against the
//  leaf (§4.4.3) and unverifiable-anything is fatal. The client Finished closes the §7
//  choreography: only after it verifies do the application READ keys install and the
//  resumption master secret derive — no path leaves keys half-installed.
//

internal import Crypto

extension TLSServerConnection {
    /// §4.4.2: the client Certificate — emptiness judged by mode, a presented chain run
    /// through the 3c trust seam (async — hence this arm lives on the async dispatch).
    mutating func processClientCertificate(
        _ message: TLSHandshakeCoalescer.Message
    ) async throws(TLSHandshakeError) {
        guard let chain = try admitClientCertificate(message) else {
            return  // empty chain, allowed by mode — no CertificateVerify follows
        }
        if let validator = configuration.clientChainValidator {
            // RFC 5280 §6 path validation at Certificate receipt — before the
            // CertificateVerify is even read (§4.4.2.4: "If the server ... the certificate
            // chain ... is unacceptable ... it MAY ... abort the handshake"; this engine
            // does, fail closed, with the verdict's §6.2 alert).
            switch await validator.validate(chainDER: chain) {
                case .accepted:
                    break
                case .rejected(let rejection):
                    throw .clientChainRejected(rejection)
            }
        }
        state = .expectingClientCertificateVerify
    }

    /// The synchronous §4.4.2 Certificate intake shared by both drives (Phase 3d).
    ///
    /// Decode, transcript, the emptiness-by-mode gate. Returns the presented chain still
    /// owing trust validation, or nil when an EMPTY chain already settled the state.
    mutating func admitClientCertificate(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) -> [[UInt8]]? {
        let chain = try TLSCertificateCodec.parseClientCertificate(message)
        transcript?.append(message.raw)
        clientCertificateChain = chain
        guard !chain.isEmpty else {
            guard configuration.clientAuthentication != .required else {
                throw .certificateRequired  // §4.4.2.4 — abort, fail closed
            }
            state = .expectingClientFinished  // §4.4.2: no cert ⇒ no CertificateVerify
            return nil
        }
        return chain
    }

    /// §4.4.3: the client CertificateVerify — scheme in our CertificateRequest offer, leaf
    /// SPKI located, signature verified over the transcript through the client Certificate.
    mutating func processClientCertificateVerify(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        let verify = try TLSCertificateVerify.parse(message)
        guard clientAuthSchemes.contains(verify.scheme) else {
            // §4.4.3: "If sent by a client, the signature algorithm used in the signature
            // MUST be one of those present in the supported_signature_algorithms field of
            // the ... CertificateRequest".
            throw .illegalParameter("CertificateVerify scheme not offered")
        }
        guard configuration.certificateVerifier.supports(verify.scheme) else {
            throw .unverifiableCertificate(verify.scheme)  // fail closed, both modes
        }
        guard let transcriptHash = transcript?.currentHash, let leaf = clientCertificateChain.first
        else {
            throw .internalError("client CertificateVerify before Certificate")  // unreachable
        }
        let verified = configuration.certificateVerifier.verify(
            scheme: verify.scheme,
            signature: verify.signature,
            content: TLSCertificateVerify.signedContent(
                context: TLSCertificateVerify.clientContext,  // role-bound (§4.4.3)
                transcriptHash: transcriptHash
            ),
            subjectPublicKeyInfoDER: try DERPublicKeyLocator.subjectPublicKeyInfo(
                inCertificateDER: leaf
            )
        )
        guard verified else {
            throw .invalidCertificateVerify  // §4.4.3 — decrypt_error
        }
        transcript?.append(message.raw)
        state = .expectingClientFinished
    }

    /// §4.4.4: the client Finished — constant-time verification, then the final §7 steps.
    mutating func processClientFinished(
        _ message: TLSHandshakeCoalescer.Message, into events: inout [TLSServerEvent]
    ) throws(TLSHandshakeError) {
        guard let suite = selectedSuite, let group = selectedGroup, var running = transcript,
            let ladder = schedule, let clientSecret = clientHandshakeSecret,
            let applicationSecret = clientApplicationSecret
        else {
            throw .internalError("client Finished before the server flight")  // unreachable
        }
        let verifyData = try TLSFinishedCodec.parseVerifyData(message, hash: suite.hash)
        let verified = suite.hash.isValidAuthenticationCode(
            verifyData,
            key: ladder.finishedKey(for: clientSecret),
            message: running.currentHash  // through everything before this Finished (§4.4.4)
        )
        guard verified else {
            throw .invalidFinished  // §4.4.4 — decrypt_error
        }
        running.append(message.raw)
        record.earlyDataSkipBudget = nil  // §4.2.10: the second flight has begun
        do {
            try record.installReadKeys(suite: suite, trafficSecret: applicationSecret)
        }
        catch {
            throw .record(error)
        }
        resumptionMaster = try? ladder.resumptionMasterSecret(
            transcriptHash: running.currentHash  // §7.1: CH..client Finished
        )
        transcript = running
        let outcome = TLSNegotiatedParameters(
            cipherSuite: suite,
            group: group,
            alpnProtocol: selectedAlpn,
            serverName: clientServerName,
            resumed: resumed,
            usedHelloRetry: sentHelloRetry,
            clientCertificateChainDER: clientCertificateChain,
            peerRecordSizeLimit: peerRecordSizeLimit
        )
        negotiated = outcome
        state = .connected
        events.append(.handshakeCompleted(outcome))
    }
}
