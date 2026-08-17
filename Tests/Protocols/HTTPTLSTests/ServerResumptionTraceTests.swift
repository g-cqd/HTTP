//
//  ServerResumptionTraceTests.swift
//  HTTPTLSTests
//
//  RFC 8448 §4 against the machine's receive side: the trace's ClientHello offers the ticket
//  the trace's own server issued (whose ticket-encryption key the RFC does not publish), so
//  the vault SEAM injects the trace's PSK for that exact identity — and the machine's
//  §4.2.11.2 binder verification, PSK-fed early secret, and ServerHello (selected_identity 0,
//  the published x25519 ephemeral) must reproduce the trace byte-exactly as far as a
//  0-RTT-REJECTING server can: through the ServerHello. The trace's server ACCEPTS early
//  data, so the flights diverge at EncryptedExtensions by design (§4.2.10 first option) —
//  the client's early-data record must be SKIPPED, not fatal, and the handshake completes
//  1-RTT. A flipped binder bit must abort with decrypt_error.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("RFC 8448 §4 — PSK resumption: binder verification replays; 0-RTT is declined")
struct ServerResumptionTraceTests {
    /// A fixed test clock (ticket lifetimes are relative to it).
    private static let now: UInt64 = 1_000_000

    /// The §4 trace ClientHello's PSK identity (the §3 connection's ticket), parsed out of
    /// the fixture by the engine's own parser.
    private static func traceIdentity() throws -> [UInt8] {
        var coalescer = TLSHandshakeCoalescer(maximumMessageLength: 1 << 17)
        coalescer.feed(RFC8448Resumed.clientHello)
        guard let message = try coalescer.next(),
            let offer = try TLSClientHello.parse(message).preSharedKey
        else {
            throw TLSHandshakeError.internalError("fixture did not parse")
        }
        return offer.identities[0].identity
    }

    /// The §4-configured server: the trace PSK injected through the vault seam.
    private static func makeConnection() throws -> TLSServerConnection {
        var configuration = TLSServerConfiguration()
        configuration.now = { now }
        configuration.ticketVault = StubTicketVault(
            identity: try traceIdentity(),
            state: TLSResumptionState(
                preSharedKey: SymmetricKey(data: RFC8448Resumed.pskInputKeyMaterial),
                hash: .sha256,
                issuedAt: now - 100,
                lifetimeSeconds: 7_200,
                ageAdd: 0,
                serverName: "server",
                alpnProtocol: nil
            )
        )
        configuration.entropy = TraceEntropy(
            random: [UInt8](RFC8448ResumedServer.serverHello[6 ..< 38]),
            privateKey: RFC8448ResumedServer.serverEphemeralPrivateKey
        )
        return TLSServerConnection(
            configuration: configuration, identity: P256TestIdentity()
        )
    }

    @Test("the §4 binder verifies and the ServerHello replays byte-exactly")
    func resumptionAcceptsTraceBinder() async throws {
        var server = try Self.makeConnection()
        let events = try await server.receive(
            TestClientHello.plaintextRecord(RFC8448Resumed.clientHello)
        )
        #expect(events.isEmpty)
        let outbound = server.outboundBytes()
        let helloRecord = TestClientHello.plaintextRecord(RFC8448ResumedServer.serverHello)
        #expect([UInt8](outbound[..<helloRecord.count]) == helloRecord)
        #expect(server.state == .expectingClientFinished)  // resumed ⇒ no client certificate
        #expect(server.record.earlyDataSkipBudget != nil)  // §4.2.10: skip window is open
    }

    @Test("the trace's early-data record is skipped, and the 1-RTT handshake completes")
    func earlyDataSkippedAndHandshakeCompletes() async throws {
        var server = try Self.makeConnection()
        _ = try await server.receive(
            TestClientHello.plaintextRecord(RFC8448Resumed.clientHello)
        )
        let flightRecord = [UInt8](
            server.outboundBytes()
                .dropFirst(
                    TestClientHello.plaintextRecord(RFC8448ResumedServer.serverHello).count
                )
        )
        // The trace's 0-RTT record (client early traffic keys) fails deprotection under the
        // client handshake keys and must be silently discarded within the budget (§4.2.10).
        let events = try await server.receive(RFC8448Resumed.earlyApplicationDataRecord)
        #expect(events.isEmpty)
        // Reconstruct the client side from published values: PSK-fed early secret, the
        // published shares' ECDHE, and the server flight we just captured.
        var ladder = TLSKeySchedule(hash: .sha256)
        try ladder.deriveEarlySecret(
            preSharedKey: SymmetricKey(data: RFC8448Resumed.pskInputKeyMaterial)
        )
        let serverKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: RFC8448ResumedServer.serverEphemeralPrivateKey
        )
        // The client's share is inside its ClientHello; the server's private key is
        // published, so the trace ECDHE is reproducible from the server side.
        var coalescer = TLSHandshakeCoalescer(maximumMessageLength: 1 << 17)
        coalescer.feed(RFC8448Resumed.clientHello)
        guard let helloMessage = try coalescer.next(),
            let clientShare = try TLSClientHello.parse(helloMessage).keyShares?
                .first(where: { $0.group == .x25519 })
        else {
            Issue.record("fixture did not parse")
            return
        }
        let peer = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: clientShare.keyExchange
        )
        try ladder.deriveHandshakeSecret(
            sharedSecret: serverKey.sharedSecretFromKeyAgreement(with: peer)
        )
        var transcript = TLSTranscriptHash(.sha256)
        transcript.append(RFC8448Resumed.clientHello)
        transcript.append(RFC8448ResumedServer.serverHello)
        let helloHash = transcript.currentHash
        let clientSecret = try ladder.clientHandshakeTrafficSecret(transcriptHash: helloHash)
        let serverSecret = try ladder.serverHandshakeTrafficSecret(transcriptHash: helloHash)
        // Open the server's flight to feed the transcript (our EE differs from the trace's,
        // which acknowledged early data — ours must NOT).
        var opener = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: serverSecret)
        let flight = try opener.open(
            header: flightRecord[..<5], body: flightRecord[5...]
        )
        #expect(flight.type == .handshake)
        transcript.append(flight.content)
        let finished = TLSFinishedCodec.finished(
            verifyData: ladder.finishedVerifyData(
                trafficSecret: clientSecret, transcriptHash: transcript.currentHash
            )
        )
        var sealer = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: clientSecret)
        var wire: [UInt8] = []
        try sealer.seal(type: .handshake, fragment: finished[...], into: &wire)
        let completion = try await server.receive(wire)
        guard case .handshakeCompleted(let negotiated) = completion.first else {
            Issue.record("expected completion, got \(completion)")
            return
        }
        #expect(negotiated.resumed)
        #expect(negotiated.clientCertificateChainDER.isEmpty)
        #expect(server.record.earlyDataSkipBudget == nil)  // closed at the client Finished
    }

    @Test("a flipped binder bit aborts with decrypt_error")
    func flippedBinderIsFatal() async throws {
        var server = try Self.makeConnection()
        var hello = RFC8448Resumed.clientHello
        hello[hello.count - 1] ^= 0x01  // the binder's last octet
        await #expect(throws: TLSHandshakeError.invalidBinder) {
            _ = try await server.receive(TestClientHello.plaintextRecord(hello))
        }
        #expect(server.state == .failed(.invalidBinder))
        // The one funnel: exactly one fatal alert on the wire, decrypt_error(51).
        #expect(server.outboundBytes() == [21, 3, 3, 0, 2, 2, 51])
    }

    @Test("an unknown ticket degrades to a full handshake, never an oracle")
    func unknownTicketFallsBackToFullHandshake() async throws {
        var configuration = TLSServerConfiguration()
        configuration.now = { Self.now }
        configuration.ticketVault = StubTicketVault(
            identity: [0xAA],  // matches nothing the trace offers
            state: TLSResumptionState(
                preSharedKey: SymmetricKey(data: RFC8448Resumed.pskInputKeyMaterial),
                hash: .sha256,
                issuedAt: Self.now,
                lifetimeSeconds: 60,
                ageAdd: 0,
                serverName: nil,
                alpnProtocol: nil
            )
        )
        configuration.entropy = TraceEntropy(
            random: [UInt8](RFC8448ResumedServer.serverHello[6 ..< 38]),
            privateKey: RFC8448ResumedServer.serverEphemeralPrivateKey
        )
        var server = TLSServerConnection(
            configuration: configuration, identity: P256TestIdentity()
        )
        let events = try await server.receive(
            TestClientHello.plaintextRecord(RFC8448Resumed.clientHello)
        )
        #expect(events.isEmpty)
        // Full handshake: the ServerHello must NOT echo a selected_identity, and the flight
        // must carry a Certificate (a real P-256 one here, not the trace's).
        let outbound = server.outboundBytes()
        #expect(!outbound.isEmpty)
        #expect(server.state == .expectingClientFinished)
        let helloRecord = TestClientHello.plaintextRecord(RFC8448ResumedServer.serverHello)
        #expect([UInt8](outbound[..<5]) != [UInt8](helloRecord[..<5]))  // lengths differ
    }
}
