//
//  SimpleTraceRecordLayerTests.swift
//  HTTPTLSTests
//
//  RFC 8448 §3 driven end-to-end through the sans-I/O ``TLSRecordLayer`` playing its real role
//  — the SERVER: the client's published records go in through `receive`, the server's published
//  records must come out of `outboundBytes()` byte-exactly, with the §7.1 key ladder advanced
//  exactly where the trace advances it. This is the engine-level replay of the whole trace;
//  §7's compatibility-mode CCS records exercise the D.4 tolerance window on the same engine.
//

import Crypto
internal import HTTPTLS
import Testing

@Suite("RFC 8448 — the record layer replays the traces as the server")
struct SimpleTraceRecordLayerTests {
    @Test("the §3 Simple 1-RTT exchange replays byte-exactly through the layer")
    func simpleTraceReplays() throws {
        var server = TLSRecordLayer()
        // ClientHello arrives unprotected.
        var events = try server.receive(RFC8448Simple.clientHelloRecord)
        #expect(events == [.handshake(RFC8448Simple.clientHello)])
        // ServerHello leaves unprotected — and must frame byte-exactly (0x0303 version).
        try server.send(handshake: RFC8448Simple.serverHello)
        #expect(server.outboundBytes() == RFC8448Simple.serverHelloRecord)
        // The server's flight rides the handshake write keys.
        try server.installWriteKeys(
            suite: .aes128GcmSha256,
            trafficSecret: SymmetricKey(data: RFC8448Simple.serverHandshakeTrafficSecret)
        )
        try server.send(handshake: RFC8448Simple.serverFlight)
        #expect(server.outboundBytes() == RFC8448Simple.serverFlightRecord)
        // The client's Finished arrives under the client handshake keys.
        try server.installReadKeys(
            suite: .aes128GcmSha256,
            trafficSecret: SymmetricKey(data: RFC8448Simple.clientHandshakeTrafficSecret)
        )
        events = try server.receive(RFC8448Simple.clientFinishedRecord)
        #expect(events == [.handshake(RFC8448Simple.clientFinished)])
        // Both directions climb to the application epoch.
        try server.installWriteKeys(
            suite: .aes128GcmSha256,
            trafficSecret: SymmetricKey(data: RFC8448Simple.serverApplicationTrafficSecret)
        )
        try server.installReadKeys(
            suite: .aes128GcmSha256,
            trafficSecret: SymmetricKey(data: RFC8448Simple.clientApplicationTrafficSecret)
        )
        // NewSessionTicket (handshake under app keys, sequence 0).
        try server.send(handshake: RFC8448Simple.newSessionTicket)
        #expect(server.outboundBytes() == RFC8448Simple.newSessionTicketRecord)
        // The client's application data and close_notify arrive in one feed.
        events = try server.receive(
            RFC8448Simple.clientApplicationDataRecord + RFC8448Simple.clientAlertRecord
        )
        let clientClose = TLSAlert(
            level: RFC8448Simple.clientAlert[0],
            description: TLSAlertDescription(rawValue: RFC8448Simple.clientAlert[1])
        )
        #expect(
            events == [
                .applicationData(RFC8448Simple.clientApplicationData), .alert(clientClose)
            ]
        )
        // The server answers with its application data (sequence 1) and close_notify (2).
        try server.send(applicationData: RFC8448Simple.serverApplicationData)
        #expect(server.outboundBytes() == RFC8448Simple.serverApplicationDataRecord)
        try server.send(
            alert: TLSAlert(
                level: RFC8448Simple.serverAlert[0],
                description: TLSAlertDescription(rawValue: RFC8448Simple.serverAlert[1])
            )
        )
        #expect(server.outboundBytes() == RFC8448Simple.serverAlertRecord)
        #expect(server.readEpoch == .application)
        #expect(server.writeEpoch == .application)
    }

    @Test("the §3 client records replay identically when fed one octet at a time")
    func simpleTraceReplaysDribbled() throws {
        var server = TLSRecordLayer()
        var events: [TLSRecordEvent] = []
        for byte in RFC8448Simple.clientHelloRecord {
            events += try server.receive([byte])
        }
        #expect(events == [.handshake(RFC8448Simple.clientHello)])
        try server.installReadKeys(
            suite: .aes128GcmSha256,
            trafficSecret: SymmetricKey(data: RFC8448Simple.clientHandshakeTrafficSecret)
        )
        events = []
        for byte in RFC8448Simple.clientFinishedRecord {
            events += try server.receive([byte])
        }
        #expect(events == [.handshake(RFC8448Simple.clientFinished)])
    }

    @Test("the §7 compatibility-mode CCS records are dropped inside the D.4 window")
    func compatibilityModeCCSTolerated() throws {
        var server = TLSRecordLayer()
        var events = try server.receive(RFC8448Compat.clientHelloRecord)
        #expect(events.count == 1)
        // §7's client CCS arrives between ClientHello and Finished — dropped, no event.
        events = try server.receive(RFC8448Compat.changeCipherSpecRecord)
        #expect(events.isEmpty)
        // Still dropped after the read side climbs to the handshake epoch.
        try server.installReadKeys(
            suite: .aes128GcmSha256,
            trafficSecret: SymmetricKey(data: RFC8448Simple.clientHandshakeTrafficSecret)
        )
        events = try server.receive(RFC8448Compat.changeCipherSpecRecord)
        #expect(events.isEmpty)
    }

    @Test("a CCS before any handshake record is fatal (outside the §5 window)")
    func prematureCCSRejected() {
        var server = TLSRecordLayer()
        #expect(throws: TLSRecordError.unexpectedChangeCipherSpec) {
            _ = try server.receive(RFC8448Compat.changeCipherSpecRecord)
        }
    }

    @Test("a CCS after the read side reaches the application epoch is fatal (§5)")
    func lateCCSRejected() throws {
        var server = TLSRecordLayer()
        _ = try server.receive(RFC8448Simple.clientHelloRecord)
        try server.installReadKeys(
            suite: .aes128GcmSha256,
            trafficSecret: SymmetricKey(data: RFC8448Simple.clientHandshakeTrafficSecret)
        )
        try server.installReadKeys(
            suite: .aes128GcmSha256,
            trafficSecret: SymmetricKey(data: RFC8448Simple.clientApplicationTrafficSecret)
        )
        #expect(throws: TLSRecordError.unexpectedChangeCipherSpec) {
            _ = try server.receive(RFC8448Compat.changeCipherSpecRecord)
        }
    }
}
