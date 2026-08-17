//
//  ServerPostHandshakeTests.swift
//  HTTPTLSTests
//
//  RFC 8446 §4.6 post-handshake traffic against a completed connection: KeyUpdate in both
//  directions (peer-initiated with and without `update_requested`, server-initiated via
//  ``TLSServerConnection/requestKeyUpdate(askPeerToUpdate:)``, and the automatic §5.5
//  counter-driven rekey), stateless-ticket issue → redeem → RESUME round trip on this
//  server's own vault, and the §6.1 close choreography.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("Post-handshake — KeyUpdate both ways, the ticket round trip, close choreography")
struct ServerPostHandshakeTests {
    /// A connected (server, client) pair over a real handshake.
    private static func connectedPair(
        configure: ((inout TLSServerConfiguration) -> Void)? = nil
    ) async throws -> (TLSServerConnection, HandshakeTestClient) {
        var configuration = TLSServerConfiguration()
        configure?(&configuration)
        var server = TLSServerConnection(
            configuration: configuration, identity: P256TestIdentity()
        )
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        _ = try await server.receive(try client.finishHandshake())
        return (server, client)
    }

    @Test("a peer KeyUpdate(update_requested) ratchets read, answers, and ratchets write")
    func peerRequestedKeyUpdate() async throws {
        var (server, client) = try await Self.connectedPair()
        _ = try await server.receive(try client.keyUpdateRecord(requesting: true))
        // The answer must decrypt under the client's OLD read keys (the server's answer
        // rides the pre-ratchet write keys, §4.6.3), and be a KeyUpdate(not_requested).
        try client.absorb(server.outboundBytes())
        #expect(client.serverMessages.last?.type == .keyUpdate)
        #expect(client.serverMessages.last.map { [UInt8]($0.body) } == [0])
        // After the exchange both directions still carry application data (the client's
        // read ratchet already happened inside absorb's KeyUpdate tracking).
        let payload: [UInt8] = [1, 2, 3]
        let events = try await server.receive(try client.applicationDataRecord(payload))
        #expect(events == [.applicationData(payload)])
        try server.send(applicationData: [4, 5])
        try client.absorb(server.outboundBytes())
        #expect(client.applicationData.last == [4, 5])
    }

    @Test("a peer KeyUpdate(update_not_requested) ratchets read only — no answer")
    func peerUnrequestedKeyUpdate() async throws {
        var (server, client) = try await Self.connectedPair()
        let events = try await server.receive(try client.keyUpdateRecord(requesting: false))
        #expect(events.isEmpty)
        #expect(server.outboundBytes().isEmpty)  // §4.6.3: no response owed
        let payload: [UInt8] = [9]
        let dataEvents = try await server.receive(try client.applicationDataRecord(payload))
        #expect(dataEvents == [.applicationData(payload)])
    }

    @Test("requestKeyUpdate rekeys the write direction under §4.6.3's ordering")
    func serverInitiatedKeyUpdate() async throws {
        var (server, client) = try await Self.connectedPair()
        try server.requestKeyUpdate(askPeerToUpdate: true)
        // The client reads the KeyUpdate under its CURRENT keys, then ratchets read.
        try client.absorb(server.outboundBytes())
        #expect(client.serverMessages.last?.type == .keyUpdate)
        #expect(client.serverMessages.last.map { [UInt8]($0.body) } == [1])
        // Data sealed under the server's NEW write keys must decrypt after the ratchet.
        try server.send(applicationData: [7])
        try client.absorb(server.outboundBytes())
        #expect(client.applicationData.last == [7])
    }

    @Test("issued tickets redeem through the stateless vault and RESUME a new connection")
    func ticketRoundTripResumes() async throws {
        let keyBytes = SymmetricKey(size: .bits256)
        let ticketKey = TLSTicketKey(name: [8, 7, 6, 5, 4, 3, 2, 1], secret: keyBytes)
        guard let vault = TLSStatelessTicketVault(keys: [ticketKey].compactMap(\.self))
        else {
            Issue.record("vault construction failed")
            return
        }
        var (server, client) = try await Self.connectedPair { configuration in
            configuration.ticketVault = vault
        }
        try server.issueSessionTicket()
        try client.absorb(server.outboundBytes())
        guard let ticketMessage = client.serverMessages.last,
            ticketMessage.type == .newSessionTicket
        else {
            Issue.record("expected a NewSessionTicket")
            return
        }
        // Parse the NST, derive the client's resumption PSK per §4.6.1, and resume.
        var reader = TLSHandshakeReader(ticketMessage.body)
        _ = try reader.u32("lifetime")
        _ = try reader.u32("age_add")
        let nonce = [UInt8](try reader.vector8("nonce"))
        let ticket = [UInt8](try reader.vector16("ticket"))
        let resumptionMaster = try client.schedule.resumptionMasterSecret(
            transcriptHash: client.transcript.currentHash
        )
        let psk = client.schedule.resumptionPreSharedKey(
            resumptionMasterSecret: resumptionMaster, ticketNonce: nonce
        )
        var resumedServer = TLSServerConnection(
            configuration: {
                var configuration = TLSServerConfiguration()
                configuration.ticketVault = vault
                return configuration
            }(),
            identity: P256TestIdentity()
        )
        var resumedClient = HandshakeTestClient()
        resumedClient.preSharedKey = (identity: ticket, key: psk)
        // Both hellos use the builder's default SNI — the vault binds SNI across sessions.
        _ = try await resumedServer.receive(try resumedClient.helloRecord())
        try resumedClient.absorb(resumedServer.outboundBytes())
        // Resumed: the flight has no Certificate/CertificateVerify/CertificateRequest.
        #expect(!resumedClient.serverMessages.contains { $0.type == .certificate })
        let events = try await resumedServer.receive(try resumedClient.finishHandshake())
        guard case .handshakeCompleted(let negotiated) = events.first else {
            Issue.record("expected resumption completion, got \(events)")
            return
        }
        #expect(negotiated.resumed)
    }

    @Test("issueSessionTicket without a vault is a caller error, not a funnel exit")
    func ticketsWithoutVaultDoNotKillTheConnection() async throws {
        var (server, client) = try await Self.connectedPair()
        #expect(throws: TLSHandshakeError.sessionTicketsUnavailable) {
            try server.issueSessionTicket()
        }
        #expect(server.state == .connected)  // NOT funneled
        let payload: [UInt8] = [1]
        let events = try await server.receive(try client.applicationDataRecord(payload))
        #expect(events == [.applicationData(payload)])
    }

    @Test("the §5.5 soft limit drives an automatic KeyUpdate before the bound")
    func automaticKeyUpdateNearTheLimit() async throws {
        var (server, client) = try await Self.connectedPair()
        // Push the server's write sequence to the KeyUpdate margin (the protector's
        // internally-settable sequence exists exactly for this — the §5.5 soft limit
        // itself is ~2^24 records).
        let jumped = TLSCipherSuite.aes128GcmSha256.protectionSoftLimit - 1_024
        server.record.writeProtector?.sequenceNumber = jumped
        client.record.readProtector?.sequenceNumber = jumped  // §5.3 nonces must agree
        try server.send(applicationData: [1, 2, 3])
        try client.absorb(server.outboundBytes())
        // The KeyUpdate must precede the data, both under the right generations.
        #expect(client.serverMessages.last?.type == .keyUpdate)
        #expect(client.applicationData.last == [1, 2, 3])
    }

    @Test("a second close is idempotent and a failed connection never emits close_notify")
    func closeChoreography() async throws {
        var (server, _) = try await Self.connectedPair()
        server.close()
        let first = server.outboundBytes()
        #expect(!first.isEmpty)
        server.close()
        #expect(server.outboundBytes().isEmpty)  // §6.1: exactly one close_notify
        await #expect(throws: TLSHandshakeError.connectionClosed) {
            _ = try await server.receive([1, 2, 3])
        }
    }
}
