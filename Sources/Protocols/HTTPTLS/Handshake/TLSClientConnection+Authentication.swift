//
//  TLSClientConnection+Authentication.swift
//  HTTPTLS
//
//  RFC 8446 §4.3 / §4.4 — EncryptedExtensions, CertificateRequest, the server's Certificate
//  (RFC 5280 path + RFC 6125 host validation), CertificateVerify, and Finished, then the client's
//  Finished flight and the application traffic keys, for ``TLSClientConnection``.
//

internal import Crypto

extension TLSClientConnection {
    mutating func processEncryptedExtensions(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        let extensions = try TLSClientCodec.parseEncryptedExtensions(message)
        if let alpn = extensions.alpnProtocol {
            guard configuration.alpnProtocols.contains(alpn) else {
                throw .illegalParameter("unoffered ALPN protocol selected")  // RFC 7301 §3.2
            }
            selectedAlpn = alpn
        }
        if let limit = extensions.recordSizeLimit {
            peerRecordSizeLimit = limit
            record.maxOutboundFragmentLength = max(1, limit - 1)  // RFC 8449 §4: minus content type
        }
        transcript?.append(message.raw)
        state = .expectingServerCertificateOrRequest
    }

    /// §4.3.2: a CertificateRequest — this client has no certificate, so it will answer with an
    /// empty Certificate (§4.4.2) and no CertificateVerify.
    mutating func processCertificateRequest(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        var reader = TLSHandshakeReader(message.body)
        let context = try reader.vector8("CertificateRequest.certificate_request_context")
        guard context.isEmpty else {
            throw .illegalParameter("non-empty handshake CertificateRequest context")
        }
        _ = try reader.vector16("CertificateRequest.extensions")
        try reader.expectEnd(of: "CertificateRequest")
        serverRequestedClientCertificate = true
        transcript?.append(message.raw)
        state = .expectingServerCertificate
    }

    mutating func processServerCertificate(
        _ message: TLSHandshakeCoalescer.Message
    ) async throws(TLSHandshakeError) {
        serverCertificateChain = try TLSCertificateCodec.parseServerCertificate(message)
        try await chainValidator.requireAccepted(serverCertificateChain)  // RFC 5280 §6 + RFC 6125
        transcript?.append(message.raw)
        state = .expectingServerCertificateVerify
    }

    mutating func processServerCertificateVerify(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        try TLSCertificateVerify.verifyPeer(
            message,
            expecting: serverSignatureExpectation,
            chain: serverCertificateChain,
            transcript: &transcript
        )
        state = .expectingServerFinished
    }

    /// §4.4.3: the server signs under a scheme we offered, with the server context.
    private var serverSignatureExpectation: TLSCertificateVerify.PeerExpectation {
        .init(
            offered: configuration.signatureSchemes,
            verifier: configuration.certificateVerifier,
            context: TLSCertificateVerify.serverContext
        )
    }

    mutating func processServerFinished(
        _ message: TLSHandshakeCoalescer.Message,
        into events: inout [TLSClientEvent]
    ) throws(TLSHandshakeError) {
        guard let suite = selectedSuite, var ladder = schedule,
            let serverSecret = serverHandshakeSecret,
            let clientSecret = clientHandshakeSecret, let beforeFinished = transcript?.currentHash
        else {
            throw .internalError("server Finished without handshake secrets")
        }
        let peerVerifyData = try TLSFinishedCodec.parseVerifyData(message, hash: suite.hash)
        let expected = ladder.finishedVerifyData(
            trafficSecret: serverSecret,
            transcriptHash: beforeFinished
        )
        guard Self.constantTimeEqual(Array(peerVerifyData), expected) else {
            throw .invalidFinished  // §4.4.4 — decrypt_error
        }
        transcript?.append(message.raw)
        let serverFinishedHash = transcript?.currentHash ?? []
        let applicationSecrets: (client: SymmetricKey, server: SymmetricKey)
        do {
            try ladder.deriveMasterSecret()
            applicationSecrets = (
                try ladder.clientApplicationTrafficSecret(transcriptHash: serverFinishedHash),
                try ladder.serverApplicationTrafficSecret(transcriptHash: serverFinishedHash)
            )
        }
        catch {
            throw .internalError("client master secret schedule")
        }
        try sendClientFinished(
            ladder: ladder,
            suite: suite,
            clientSecret: clientSecret,
            application: applicationSecrets
        )
        schedule = ladder
        let parameters = TLSNegotiatedParameters(
            cipherSuite: suite,
            group: activeGroup,
            alpnProtocol: selectedAlpn,
            serverName: configuration.serverName,
            resumed: false,
            usedHelloRetry: usedHelloRetry,
            clientCertificateChainDER: [],
            peerRecordSizeLimit: peerRecordSizeLimit
        )
        negotiated = parameters
        state = .connected
        events.append(.handshakeCompleted(parameters))
    }

    /// §4.4.4: the client flight (an empty Certificate if one was requested, then Finished) under
    /// the handshake write keys, then the application traffic keys in both directions.
    private mutating func sendClientFinished(
        ladder: TLSKeySchedule,
        suite: TLSCipherSuite,
        clientSecret: SymmetricKey,
        application: (client: SymmetricKey, server: SymmetricKey)
    ) throws(TLSHandshakeError) {
        var flight: [UInt8] = []
        if serverRequestedClientCertificate {
            let empty = TLSCertificateCodec.certificate(chainDER: [])
            transcript?.append(empty)
            flight.append(contentsOf: empty)
        }
        let verifyData = ladder.finishedVerifyData(
            trafficSecret: clientSecret,
            transcriptHash: transcript?.currentHash ?? []
        )
        let finished = TLSFinishedCodec.finished(verifyData: verifyData)
        transcript?.append(finished)
        flight.append(contentsOf: finished)
        try emit(handshake: flight)
        do {
            try record.installReadKeys(suite: suite, trafficSecret: application.server)
            try record.installWriteKeys(suite: suite, trafficSecret: application.client)
        }
        catch {
            throw .record(error)
        }
    }

    private static func constantTimeEqual(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }
        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }

    mutating func maintainKeyUpdates() throws(TLSHandshakeError) {
        guard state == .connected else {
            return
        }
        try keyUpdates.maintain(record: &record)
    }
}
