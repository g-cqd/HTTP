//
//  ServerSimpleTraceTests.swift
//  HTTPTLSTests
//
//  RFC 8448 §3 driven end-to-end through ``TLSServerConnection`` — the WHOLE machine this
//  time, not just the record layer: the trace's ClientHello goes in, and the machine's own
//  negotiation, transcript, key schedule, and encoders must reproduce the trace's ServerHello
//  and complete server flight BYTE-EXACTLY, then verify the trace's client Finished and
//  finish with the trace's application-data and close_notify records. The injection seams
//  carry the trace's published inputs: server random + x25519 ephemeral through
//  ``TraceEntropy``, the certificate and (randomized, hence published) RSA-PSS
//  CertificateVerify signature through ``TraceServerIdentity``.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("RFC 8448 §3 — the server machine replays the Simple 1-RTT trace byte-exactly")
struct ServerSimpleTraceTests {
    /// The trace-configured connection: §3's negotiation surface, injected inputs.
    private static func makeConnection() throws -> TLSServerConnection {
        let flight = try RFC8448Flight(RFC8448Simple.serverFlight)
        var configuration = TLSServerConfiguration()
        configuration.supportedGroupsHint = [
            .x25519, .secp256r1, .secp384r1, .secp521r1,
            TLSNamedGroup(rawValue: 0x0100), TLSNamedGroup(rawValue: 0x0101),
            TLSNamedGroup(rawValue: 0x0102), TLSNamedGroup(rawValue: 0x0103),
            TLSNamedGroup(rawValue: 0x0104)
        ]
        configuration.entropy = TraceEntropy(
            random: [UInt8](RFC8448Simple.serverHello[6 ..< 38]),
            privateKey: RFC8448Simple.serverEphemeralPrivateKey
        )
        let ticketKey = TLSTicketKey(
            name: [1, 2, 3, 4, 5, 6, 7, 8], secret: SymmetricKey(size: .bits256)
        )
        configuration.ticketVault = TLSStatelessTicketVault(
            keys: [ticketKey].compactMap(\.self)
        )
        return TLSServerConnection(
            configuration: configuration,
            identity: TraceServerIdentity(
                certificateChainDER: [flight.certificateDER],
                signature: TLSSignature(
                    scheme: flight.certificateVerify.scheme,
                    bytes: flight.certificateVerify.signature
                )
            )
        )
    }

    @Test("the §3 exchange replays byte-exactly end to end")
    func simpleTraceReplays() async throws {
        var server = try Self.makeConnection()
        // ClientHello in → ServerHello + the whole flight out, byte-exact.
        var events = try await server.receive(RFC8448Simple.clientHelloRecord)
        #expect(events.isEmpty)
        #expect(
            server.outboundBytes()
                == RFC8448Simple.serverHelloRecord + RFC8448Simple.serverFlightRecord
        )
        #expect(server.state == .expectingClientFinished)
        // The trace's client Finished must verify and complete the handshake.
        events = try await server.receive(RFC8448Simple.clientFinishedRecord)
        let expected = TLSNegotiatedParameters(
            cipherSuite: .aes128GcmSha256,
            group: .x25519,
            alpnProtocol: nil,
            serverName: "server",
            resumed: false,
            usedHelloRetry: false,
            clientCertificateChainDER: [],
            peerRecordSizeLimit: 16_385
        )
        #expect(events == [.handshakeCompleted(expected)])
        #expect(server.state == .connected)
        // One NewSessionTicket consumes application-write sequence 0 (as the trace's does);
        // its bytes are vault-specific, but the record must exist and parse as handshake.
        try server.issueSessionTicket()
        let ticketRecord = server.outboundBytes()
        #expect(ticketRecord.first == 23)  // sealed under the application keys
        // The trace's application-data exchange, in trace order: client data, server data
        // (sequence 1), client close_notify, server close_notify (sequence 2) — byte-exact.
        events = try await server.receive(RFC8448Simple.clientApplicationDataRecord)
        #expect(events == [.applicationData(RFC8448Simple.clientApplicationData)])
        try server.send(applicationData: RFC8448Simple.serverApplicationData)
        #expect(server.outboundBytes() == RFC8448Simple.serverApplicationDataRecord)
        events = try await server.receive(RFC8448Simple.clientAlertRecord)
        #expect(events == [.peerClosed])
        #expect(server.state == .closed)
        server.close()  // §6.1: our close_notify is owed even after the peer's
        #expect(server.outboundBytes() == RFC8448Simple.serverAlertRecord)
    }

    @Test("the §3 exchange replays identically when fed one octet at a time")
    func simpleTraceReplaysDribbled() async throws {
        var server = try Self.makeConnection()
        var events: [TLSServerEvent] = []
        for byte in RFC8448Simple.clientHelloRecord {
            events += try await server.receive([byte])
        }
        #expect(events.isEmpty)
        #expect(
            server.outboundBytes()
                == RFC8448Simple.serverHelloRecord + RFC8448Simple.serverFlightRecord
        )
        for byte in RFC8448Simple.clientFinishedRecord {
            events += try await server.receive([byte])
        }
        #expect(events.count == 1)
        #expect(server.state == .connected)
    }

    @Test("D.4 middlebox-compatibility mode inserts exactly one CCS after the ServerHello")
    func compatibilityModeEmitsCCS() async throws {
        let flight = try RFC8448Flight(RFC8448Simple.serverFlight)
        var configuration = TLSServerConfiguration()
        configuration.middleboxCompatibilityMode = true
        configuration.entropy = TraceEntropy(
            random: [UInt8](RFC8448Simple.serverHello[6 ..< 38]),
            privateKey: RFC8448Simple.serverEphemeralPrivateKey
        )
        var server = TLSServerConnection(
            configuration: configuration,
            identity: TraceServerIdentity(
                certificateChainDER: [flight.certificateDER],
                signature: TLSSignature(
                    scheme: flight.certificateVerify.scheme,
                    bytes: flight.certificateVerify.signature
                )
            )
        )
        _ = try await server.receive(RFC8448Simple.clientHelloRecord)
        let outbound = server.outboundBytes()
        // ServerHello record, then the D.4 CCS (14 03 03 00 01 01), then the sealed flight.
        let helloEnd = RFC8448Simple.serverHelloRecord.count
        #expect([UInt8](outbound[..<helloEnd]) == RFC8448Simple.serverHelloRecord)
        #expect([UInt8](outbound[helloEnd ..< helloEnd + 6]) == [20, 3, 3, 0, 1, 1])
    }
}
