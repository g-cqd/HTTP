//
//  SimpleTraceRecordProtectionTests.swift
//  HTTPTLSTests
//
//  RFC 8448 §3 record protection, byte-exact and in BOTH directions: every protected record of
//  the trace is sealed from its published payload (our seal must equal the published octets —
//  nonce, padding, tag and all) and the published record is opened back to its payload. The
//  sequence numbers are the trace's own: the server's NewSessionTicket burns application
//  sequence 0, so its application data seals at 1 and its alert at 2.
//

import Crypto
internal import HTTPTLS
import Testing

@Suite("RFC 8448 §3 — record protection round-trips byte-exactly")
struct SimpleTraceRecordProtectionTests {
    private func protector(_ secret: [UInt8]) -> TLSRecordProtector {
        TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: SymmetricKey(data: secret))
    }

    @Test("the server handshake flight seals to the published record (sequence 0)")
    func serverFlightSeals() throws {
        var sealer = protector(RFC8448Simple.serverHandshakeTrafficSecret)
        var out: [UInt8] = []
        try sealer.seal(type: .handshake, fragment: RFC8448Simple.serverFlight[...], into: &out)
        #expect(out == RFC8448Simple.serverFlightRecord)
        #expect(sealer.sequenceNumber == 1)
    }

    @Test("the published server flight record opens to the published payload")
    func serverFlightOpens() throws {
        var opener = protector(RFC8448Simple.serverHandshakeTrafficSecret)
        let record = RFC8448Simple.serverFlightRecord
        let opened = try opener.open(header: record[..<5], body: record[5...])
        #expect(opened.type == .handshake)
        #expect(opened.content == RFC8448Simple.serverFlight)
    }

    @Test("the client Finished record seals ours and opens theirs (sequence 0)")
    func clientFinishedRoundTrips() throws {
        var sealer = protector(RFC8448Simple.clientHandshakeTrafficSecret)
        var out: [UInt8] = []
        try sealer.seal(
            type: .handshake, fragment: RFC8448Simple.clientFinished[...], into: &out
        )
        #expect(out == RFC8448Simple.clientFinishedRecord)
        var opener = protector(RFC8448Simple.clientHandshakeTrafficSecret)
        let record = RFC8448Simple.clientFinishedRecord
        let opened = try opener.open(header: record[..<5], body: record[5...])
        #expect(opened.type == .handshake)
        #expect(opened.content == RFC8448Simple.clientFinished)
    }

    @Test("the server application direction replays: NST at 0, app data at 1, alert at 2")
    func serverApplicationSequenceReplays() throws {
        var sealer = protector(RFC8448Simple.serverApplicationTrafficSecret)
        var out: [UInt8] = []
        try sealer.seal(
            type: .handshake, fragment: RFC8448Simple.newSessionTicket[...], into: &out
        )
        #expect(out == RFC8448Simple.newSessionTicketRecord)
        out.removeAll()
        try sealer.seal(
            type: .applicationData,
            fragment: RFC8448Simple.serverApplicationData[...],
            into: &out
        )
        #expect(out == RFC8448Simple.serverApplicationDataRecord)
        out.removeAll()
        try sealer.seal(type: .alert, fragment: RFC8448Simple.serverAlert[...], into: &out)
        #expect(out == RFC8448Simple.serverAlertRecord)
        // And the same three published records open in order.
        var opener = protector(RFC8448Simple.serverApplicationTrafficSecret)
        let records = [
            RFC8448Simple.newSessionTicketRecord,
            RFC8448Simple.serverApplicationDataRecord,
            RFC8448Simple.serverAlertRecord
        ]
        let expectedTypes: [TLSContentType] = [.handshake, .applicationData, .alert]
        let expectedPayloads = [
            RFC8448Simple.newSessionTicket,
            RFC8448Simple.serverApplicationData,
            RFC8448Simple.serverAlert
        ]
        for (index, record) in records.enumerated() {
            let opened = try opener.open(header: record[..<5], body: record[5...])
            #expect(opened.type == expectedTypes[index], "record \(index)")
            #expect(opened.content == expectedPayloads[index], "record \(index)")
        }
    }

    @Test("the client application direction replays: app data at 0, alert at 1")
    func clientApplicationSequenceReplays() throws {
        var sealer = protector(RFC8448Simple.clientApplicationTrafficSecret)
        var out: [UInt8] = []
        try sealer.seal(
            type: .applicationData,
            fragment: RFC8448Simple.clientApplicationData[...],
            into: &out
        )
        #expect(out == RFC8448Simple.clientApplicationDataRecord)
        out.removeAll()
        try sealer.seal(type: .alert, fragment: RFC8448Simple.clientAlert[...], into: &out)
        #expect(out == RFC8448Simple.clientAlertRecord)
    }

    @Test("a record under retired handshake keys fails uniformly once application keys rule")
    func retiredKeysNeverOpen() throws {
        // The client Finished record was sealed under the handshake keys; an opener that has
        // moved to the application secret must reject it as bad_record_mac — §5.2's single
        // uniform failure, which is exactly how retired-key records die.
        var opener = protector(RFC8448Simple.clientApplicationTrafficSecret)
        let record = RFC8448Simple.clientFinishedRecord
        #expect(throws: TLSRecordError.badRecordMac) {
            _ = try opener.open(header: record[..<5], body: record[5...])
        }
    }
}
