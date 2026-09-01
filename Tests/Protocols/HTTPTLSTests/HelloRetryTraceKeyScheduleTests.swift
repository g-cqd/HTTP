//
//  HelloRetryTraceKeyScheduleTests.swift
//  HTTPTLSTests
//
//  RFC 8448 §5 (HelloRetryRequest) against the 3a machinery it exercises: the §4.4.1
//  message_hash transcript collapse, the P-256 ECDHE feed (recomputed from the published
//  private keys), and the §7.1 chain through the application traffic secrets — byte-exact.
//

import Crypto
import Testing

internal import struct Foundation.Data

@testable internal import HTTPTLS

@Suite("RFC 8448 §5 — the HelloRetryRequest key-schedule steps replay byte-exactly")
struct HelloRetryTraceKeyScheduleTests {
    private let hash = TLSHashFunction.sha256

    @Test("P-256 recomputes the published ECDHE shared secret (both roles)")
    func sharedSecretMatches() throws {
        let client = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: RFC8448HelloRetry.clientP256PrivateKey
        )
        let server = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: RFC8448HelloRetry.serverP256PrivateKey
        )
        #expect(
            client.publicKey.x963Representation
                == Data(RFC8448HelloRetry.clientP256PublicKey)
        )
        let serverView = try server.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(
                x963Representation: RFC8448HelloRetry.clientP256PublicKey
            )
        )
        let clientView = try client.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(
                x963Representation: RFC8448HelloRetry.serverP256PublicKey
            )
        )
        let expected = SymmetricKey(data: RFC8448HelloRetry.ecdheSharedSecret)
        #expect(SymmetricKey(data: serverView) == expected)
        #expect(SymmetricKey(data: clientView) == expected)
    }

    @Test("the §4.4.1 message_hash collapse reproduces the published transcript hash")
    func transcriptCollapseReplays() {
        var transcript = TLSTranscriptHash(hash)
        transcript.append(RFC8448HelloRetry.clientHello1)
        transcript.collapseForHelloRetry()
        transcript.append(RFC8448HelloRetry.helloRetryRequest)
        transcript.append(RFC8448HelloRetry.clientHello2)
        transcript.append(RFC8448HelloRetry.serverHello)
        #expect(transcript.currentHash == RFC8448HelloRetry.helloTranscriptHash)
    }

    @Test("the schedule replays the §5 chain through the application secrets")
    func scheduleReplays() throws {
        let early = hash.extract(salt: hash.zeroKey, inputKeyMaterial: hash.zeroKey)
        #expect(early == SymmetricKey(data: RFC8448HelloRetry.earlySecret))
        var schedule = TLSKeySchedule(hash: hash)
        try schedule.deriveEarlySecret()
        try schedule.deriveHandshakeSecret(
            ecdhe: SymmetricKey(data: RFC8448HelloRetry.ecdheSharedSecret)
        )
        var transcript = TLSTranscriptHash(hash)
        transcript.append(RFC8448HelloRetry.clientHello1)
        transcript.collapseForHelloRetry()
        transcript.append(RFC8448HelloRetry.helloRetryRequest)
        transcript.append(RFC8448HelloRetry.clientHello2)
        transcript.append(RFC8448HelloRetry.serverHello)
        let clientHs = try schedule.clientHandshakeTrafficSecret(
            transcriptHash: transcript.currentHash
        )
        let serverHs = try schedule.serverHandshakeTrafficSecret(
            transcriptHash: transcript.currentHash
        )
        #expect(clientHs == SymmetricKey(data: RFC8448HelloRetry.clientHandshakeTrafficSecret))
        #expect(serverHs == SymmetricKey(data: RFC8448HelloRetry.serverHandshakeTrafficSecret))
        try schedule.deriveMasterSecret()
        transcript.append(RFC8448HelloRetry.serverFlight)
        #expect(transcript.currentHash == RFC8448HelloRetry.serverFinishedTranscriptHash)
        let clientAp = try schedule.clientApplicationTrafficSecret(
            transcriptHash: transcript.currentHash
        )
        let serverAp = try schedule.serverApplicationTrafficSecret(
            transcriptHash: transcript.currentHash
        )
        let exporter = try schedule.exporterMasterSecret(transcriptHash: transcript.currentHash)
        #expect(
            clientAp == SymmetricKey(data: RFC8448HelloRetry.clientApplicationTrafficSecret)
        )
        #expect(
            serverAp == SymmetricKey(data: RFC8448HelloRetry.serverApplicationTrafficSecret)
        )
        #expect(exporter == SymmetricKey(data: RFC8448HelloRetry.exporterMasterSecret))
    }

    @Test("the §5 handshake extract reproduces the published secret in isolation")
    func handshakeExtractReplays() {
        let derivedSalt = hash.deriveSecret(
            SymmetricKey(data: RFC8448HelloRetry.earlySecret),
            label: "derived",
            transcriptHash: hash.emptyTranscriptHash
        )
        let handshake = hash.extract(
            salt: derivedSalt,
            inputKeyMaterial: SymmetricKey(data: RFC8448HelloRetry.ecdheSharedSecret)
        )
        #expect(handshake == SymmetricKey(data: RFC8448HelloRetry.handshakeSecret))
    }

    @Test("the §5 server flight seals and opens byte-exactly under the published keys")
    func serverFlightRecordReplays() throws {
        let secret = SymmetricKey(data: RFC8448HelloRetry.serverHandshakeTrafficSecret)
        let keys = TLSTrafficKeys(suite: .aes128GcmSha256, trafficSecret: secret)
        #expect(keys.key == SymmetricKey(data: RFC8448HelloRetry.serverHandshakeKey))
        #expect(keys.ivBytes == RFC8448HelloRetry.serverHandshakeIV)
        var sealer = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: secret)
        var out: [UInt8] = []
        try sealer.seal(
            type: .handshake, fragment: RFC8448HelloRetry.serverFlight[...], into: &out
        )
        #expect(out == RFC8448HelloRetry.serverFlightRecord)
        var opener = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: secret)
        let record = RFC8448HelloRetry.serverFlightRecord
        let opened = try opener.open(header: record[..<5], body: record[5...])
        #expect(opened.type == .handshake)
        #expect(opened.content == RFC8448HelloRetry.serverFlight)
    }
}
