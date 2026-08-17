//
//  ResumedTraceKeyScheduleTests.swift
//  HTTPTLSTests
//
//  RFC 8448 §4 (Resumed 0-RTT) as far as it exercises Phase 3a machinery: the §4.6.1 PSK
//  chains from §3's resumption master secret, feeds the PSK-keyed early secret, the §4.2.11.2
//  binder chain, the "c e traffic"/"e exp master" derivations, the §7.3 early traffic keys,
//  and the protected 0-RTT record — all byte-exact.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("RFC 8448 §4 — the 0-RTT early-secret derivations replay byte-exactly")
struct ResumedTraceKeyScheduleTests {
    private let hash = TLSHashFunction.sha256

    @Test("the §4 PSK is §3's resumption chain, and it keys the early secret")
    func pskChainsFromSimpleTrace() throws {
        // Cross-trace continuity: §3's res master + ticket nonce yield §4's PSK IKM.
        let schedule = TLSKeySchedule(hash: hash)
        let psk = schedule.resumptionPreSharedKey(
            resumptionMasterSecret: SymmetricKey(data: RFC8448Simple.resumptionMasterSecret),
            ticketNonce: RFC8448Simple.ticketNonce
        )
        #expect(psk == SymmetricKey(data: RFC8448Resumed.pskInputKeyMaterial))
        var resumed = TLSKeySchedule(hash: hash)
        try resumed.deriveEarlySecret(preSharedKey: psk)
        // The early secret is checked through its published children below; the extract itself:
        let early = hash.extract(salt: hash.zeroKey, inputKeyMaterial: psk)
        #expect(early == SymmetricKey(data: RFC8448Resumed.earlySecret))
    }

    @Test("the §4.2.11.2 binder chain replays byte-exactly")
    func binderChainReplays() throws {
        var schedule = TLSKeySchedule(hash: hash)
        try schedule.deriveEarlySecret(
            preSharedKey: SymmetricKey(data: RFC8448Resumed.pskInputKeyMaterial)
        )
        let binderKey = try schedule.binderKey(external: false)
        #expect(binderKey == SymmetricKey(data: RFC8448Resumed.binderKey))
        #expect(
            schedule.finishedKey(for: binderKey)
                == SymmetricKey(data: RFC8448Resumed.binderFinishedKey)
        )
        // The binder transcript is the ClientHello truncated before the binders (§4.2.11.2).
        var transcript = TLSTranscriptHash(hash)
        transcript.append(RFC8448Resumed.clientHelloBinderPrefix)
        #expect(transcript.currentHash == RFC8448Resumed.binderTranscriptHash)
        let binder = hash.authenticationCode(
            key: SymmetricKey(data: RFC8448Resumed.binderFinishedKey),
            message: transcript.currentHash
        )
        #expect(binder == RFC8448Resumed.binderValue)
    }

    @Test("the early traffic and early exporter secrets replay byte-exactly")
    func earlySecretsReplay() throws {
        var schedule = TLSKeySchedule(hash: hash)
        try schedule.deriveEarlySecret(
            preSharedKey: SymmetricKey(data: RFC8448Resumed.pskInputKeyMaterial)
        )
        var transcript = TLSTranscriptHash(hash)
        transcript.append(RFC8448Resumed.clientHello)
        #expect(transcript.currentHash == RFC8448Resumed.clientHelloTranscriptHash)
        let early = try schedule.clientEarlyTrafficSecret(transcriptHash: transcript.currentHash)
        #expect(early == SymmetricKey(data: RFC8448Resumed.clientEarlyTrafficSecret))
        let exporter = try schedule.earlyExporterMasterSecret(
            transcriptHash: transcript.currentHash
        )
        #expect(exporter == SymmetricKey(data: RFC8448Resumed.earlyExporterMasterSecret))
    }

    @Test("the early write keys and the protected 0-RTT record replay byte-exactly")
    func earlyRecordReplays() throws {
        let secret = SymmetricKey(data: RFC8448Resumed.clientEarlyTrafficSecret)
        let keys = TLSTrafficKeys(suite: .aes128GcmSha256, trafficSecret: secret)
        #expect(keys.key == SymmetricKey(data: RFC8448Resumed.earlyWriteKey))
        #expect(keys.ivBytes == RFC8448Resumed.earlyWriteIV)
        // Seal our side: the client's 0-RTT record at sequence 0 must come out byte-exact.
        var sealer = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: secret)
        var out: [UInt8] = []
        try sealer.seal(
            type: .applicationData,
            fragment: RFC8448Resumed.earlyApplicationData[...],
            into: &out
        )
        #expect(out == RFC8448Resumed.earlyApplicationDataRecord)
        // Open theirs: the published record deprotects to the published payload.
        var opener = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: secret)
        let record = RFC8448Resumed.earlyApplicationDataRecord
        let opened = try opener.open(header: record[..<5], body: record[5...])
        #expect(opened.type == .applicationData)
        #expect(opened.content == RFC8448Resumed.earlyApplicationData)
    }
}
