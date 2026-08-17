//
//  SimpleTraceKeyScheduleTests.swift
//  HTTPTLSTests
//
//  RFC 8448 §3 (Simple 1-RTT) against the §7.1 key schedule, byte-exact: the X25519 shared
//  secret is recomputed from the published private keys, every Extract and Derive-Secret must
//  reproduce the published intermediate, the incremental transcript must reproduce every
//  published hash, and the §4.4.4 finished keys/verify_data and §4.6.1 resumption PSK must
//  match. A schedule that cannot replay this trace does not merge.
//

import Crypto
import Testing

internal import struct Foundation.Data

@testable internal import HTTPTLS

@Suite("RFC 8448 §3 — the Simple 1-RTT key schedule replays byte-exactly")
struct SimpleTraceKeyScheduleTests {
    private let hash = TLSHashFunction.sha256

    @Test("X25519 recomputes the published ECDHE shared secret (both roles)")
    func sharedSecretMatches() throws {
        let client = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: RFC8448Simple.clientEphemeralPrivateKey
        )
        let server = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: RFC8448Simple.serverEphemeralPrivateKey
        )
        #expect(
            client.publicKey.rawRepresentation
                == Data(RFC8448Simple.clientEphemeralPublicKey)
        )
        let serverView = try server.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: RFC8448Simple.clientEphemeralPublicKey
            )
        )
        let clientView = try client.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: RFC8448Simple.serverEphemeralPublicKey
            )
        )
        let expected = SymmetricKey(data: RFC8448Simple.ecdheSharedSecret)
        #expect(SymmetricKey(data: serverView) == expected)
        #expect(SymmetricKey(data: clientView) == expected)
    }

    @Test("each §7.1 Extract and 'derived' salt reproduces its published value in isolation")
    func extractLadderMatches() {
        let early = hash.extract(salt: hash.zeroKey, inputKeyMaterial: hash.zeroKey)
        #expect(early == SymmetricKey(data: RFC8448Simple.earlySecret))
        let handshakeSalt = hash.deriveSecret(
            early, label: "derived", transcriptHash: hash.emptyTranscriptHash
        )
        #expect(handshakeSalt == SymmetricKey(data: RFC8448Simple.handshakeDerivedSalt))
        let handshake = hash.extract(
            salt: handshakeSalt,
            inputKeyMaterial: SymmetricKey(data: RFC8448Simple.ecdheSharedSecret)
        )
        #expect(handshake == SymmetricKey(data: RFC8448Simple.handshakeSecret))
        let masterSalt = hash.deriveSecret(
            handshake, label: "derived", transcriptHash: hash.emptyTranscriptHash
        )
        #expect(masterSalt == SymmetricKey(data: RFC8448Simple.masterDerivedSalt))
        let master = hash.extract(salt: masterSalt, inputKeyMaterial: hash.zeroKey)
        #expect(master == SymmetricKey(data: RFC8448Simple.masterSecret))
    }

    @Test("the full schedule + transcript replays every §3 traffic secret byte-exactly")
    func fullScheduleReplays() throws {
        var schedule = TLSKeySchedule(hash: hash)
        var transcript = TLSTranscriptHash(hash)
        try schedule.deriveEarlySecret()
        transcript.append(RFC8448Simple.clientHello)
        transcript.append(RFC8448Simple.serverHello)
        #expect(transcript.currentHash == RFC8448Simple.helloTranscriptHash)
        try schedule.deriveHandshakeSecret(
            ecdhe: SymmetricKey(data: RFC8448Simple.ecdheSharedSecret)
        )
        let clientHs = try schedule.clientHandshakeTrafficSecret(
            transcriptHash: transcript.currentHash
        )
        let serverHs = try schedule.serverHandshakeTrafficSecret(
            transcriptHash: transcript.currentHash
        )
        #expect(clientHs == SymmetricKey(data: RFC8448Simple.clientHandshakeTrafficSecret))
        #expect(serverHs == SymmetricKey(data: RFC8448Simple.serverHandshakeTrafficSecret))
        try schedule.deriveMasterSecret()
        transcript.append(RFC8448Simple.serverFlight)
        #expect(transcript.currentHash == RFC8448Simple.serverFinishedTranscriptHash)
        let clientAp = try schedule.clientApplicationTrafficSecret(
            transcriptHash: transcript.currentHash
        )
        let serverAp = try schedule.serverApplicationTrafficSecret(
            transcriptHash: transcript.currentHash
        )
        let exporter = try schedule.exporterMasterSecret(transcriptHash: transcript.currentHash)
        #expect(clientAp == SymmetricKey(data: RFC8448Simple.clientApplicationTrafficSecret))
        #expect(serverAp == SymmetricKey(data: RFC8448Simple.serverApplicationTrafficSecret))
        #expect(exporter == SymmetricKey(data: RFC8448Simple.exporterMasterSecret))
        transcript.append(RFC8448Simple.clientFinished)
        #expect(transcript.currentHash == RFC8448Simple.clientFinishedTranscriptHash)
        let resumption = try schedule.resumptionMasterSecret(
            transcriptHash: transcript.currentHash
        )
        #expect(resumption == SymmetricKey(data: RFC8448Simple.resumptionMasterSecret))
        let psk = schedule.resumptionPreSharedKey(
            resumptionMasterSecret: resumption, ticketNonce: RFC8448Simple.ticketNonce
        )
        #expect(psk == SymmetricKey(data: RFC8448Simple.resumptionPreSharedKey))
    }

    @Test("the §4.4.4 finished keys and verify_data replay byte-exactly")
    func finishedKeysReplay() {
        let schedule = TLSKeySchedule(hash: hash)
        let serverHs = SymmetricKey(data: RFC8448Simple.serverHandshakeTrafficSecret)
        #expect(
            schedule.finishedKey(for: serverHs)
                == SymmetricKey(data: RFC8448Simple.serverFinishedKey)
        )
        // The server's verify_data covers CH..CertificateVerify — the flight minus Finished.
        var transcript = TLSTranscriptHash(hash)
        transcript.append(RFC8448Simple.clientHello)
        transcript.append(RFC8448Simple.serverHello)
        transcript.append(Array(RFC8448Simple.serverFlight.dropLast(36)))
        let serverVerify = schedule.finishedVerifyData(
            trafficSecret: serverHs, transcriptHash: transcript.currentHash
        )
        #expect(serverVerify == RFC8448Simple.serverFinishedVerifyData)
        // The published Finished message is header ∥ verify_data — the trace agrees with itself.
        #expect(Array(RFC8448Simple.serverFinished.suffix(32)) == serverVerify)
        // The client's verify_data covers CH..server Finished.
        let clientHs = SymmetricKey(data: RFC8448Simple.clientHandshakeTrafficSecret)
        #expect(
            schedule.finishedKey(for: clientHs)
                == SymmetricKey(data: RFC8448Simple.clientFinishedKey)
        )
        let clientVerify = schedule.finishedVerifyData(
            trafficSecret: clientHs,
            transcriptHash: RFC8448Simple.serverFinishedTranscriptHash
        )
        #expect(clientVerify == RFC8448Simple.clientFinishedVerifyData)
        #expect(Array(RFC8448Simple.clientFinished.suffix(32)) == clientVerify)
    }

    @Test(
        "the §7.3 traffic keys replay byte-exactly for all four §3 directions",
        arguments: [
            ("server handshake", "serverHandshake"),
            ("client handshake", "clientHandshake"),
            ("server application", "serverApplication"),
            ("client application", "clientApplication")
        ]
    )
    func trafficKeysReplay(name: String, which: String) {
        let (secret, expectedKey, expectedIV): ([UInt8], [UInt8], [UInt8]) =
            switch which {
                case "serverHandshake":
                    (
                        RFC8448Simple.serverHandshakeTrafficSecret,
                        RFC8448Simple.serverHandshakeKey, RFC8448Simple.serverHandshakeIV
                    )
                case "clientHandshake":
                    (
                        RFC8448Simple.clientHandshakeTrafficSecret,
                        RFC8448Simple.clientHandshakeKey, RFC8448Simple.clientHandshakeIV
                    )
                case "serverApplication":
                    (
                        RFC8448Simple.serverApplicationTrafficSecret,
                        RFC8448Simple.serverApplicationKey, RFC8448Simple.serverApplicationIV
                    )
                default:
                    (
                        RFC8448Simple.clientApplicationTrafficSecret,
                        RFC8448Simple.clientApplicationKey, RFC8448Simple.clientApplicationIV
                    )
            }
        let keys = TLSTrafficKeys(
            suite: .aes128GcmSha256, trafficSecret: SymmetricKey(data: secret)
        )
        #expect(keys.key == SymmetricKey(data: expectedKey), "\(name) key")
        #expect(keys.ivBytes == expectedIV, "\(name) iv")
    }
}
