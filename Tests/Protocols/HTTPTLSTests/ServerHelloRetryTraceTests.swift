//
//  ServerHelloRetryTraceTests.swift
//  HTTPTLSTests
//
//  RFC 8448 §5 driven end-to-end through ``TLSServerConnection``: a server configured (like
//  the trace's) to accept only P-256 receives ClientHello1 carrying an x25519 share, must
//  answer with the trace's HelloRetryRequest byte-exactly (special random, key_share naming
//  0x0017, the trace's cookie via the cookie seam), then complete on ClientHello2 with the
//  trace's ServerHello and flight byte-exactly. The §4.4.1 message_hash transcript collapse
//  is proven by the flight's Finished matching — a wrong collapse breaks every secret.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("RFC 8448 §5 — the server machine replays the HelloRetryRequest trace byte-exactly")
struct ServerHelloRetryTraceTests {
    /// The trace's cookie: the §4.2.2 opaque value inside the HRR fixture (offset computed
    /// from the fixed §4.1.4 layout and asserted in the test).
    private static var traceCookie: [UInt8] {
        [UInt8](RFC8448HelloRetry.helloRetryRequest[56 ..< 170])
    }

    /// The §5-configured server: P-256 only, the trace's EE hint order, injected inputs.
    private static func makeConnection() throws -> TLSServerConnection {
        let flight = try RFC8448Flight(RFC8448HelloRetry.serverFlight)
        var configuration = TLSServerConfiguration()
        configuration.groups = [.secp256r1]
        configuration.supportedGroupsHint = [.secp256r1, .secp384r1, .x25519]
        configuration.cookieProvider = { _ in traceCookie }
        configuration.entropy = TraceEntropy(
            random: [UInt8](RFC8448HelloRetry.serverHello[6 ..< 38]),
            privateKey: RFC8448HelloRetry.serverP256PrivateKey
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

    @Test("the §5 exchange replays byte-exactly through the HRR round")
    func helloRetryTraceReplays() async throws {
        var server = try Self.makeConnection()
        // ClientHello1 (x25519 share only) → the trace's HelloRetryRequest, byte-exact.
        var events = try await server.receive(
            TestClientHello.plaintextRecord(RFC8448HelloRetry.clientHello1)
        )
        #expect(events.isEmpty)
        #expect(
            server.outboundBytes()
                == TestClientHello.plaintextRecord(RFC8448HelloRetry.helloRetryRequest)
        )
        #expect(server.state == .expectingRetriedClientHello)
        // ClientHello2 (P-256 share, echoed cookie) → ServerHello + flight, byte-exact.
        events = try await server.receive(
            TestClientHello.plaintextRecord(RFC8448HelloRetry.clientHello2)
        )
        #expect(events.isEmpty)
        #expect(
            server.outboundBytes()
                == TestClientHello.plaintextRecord(RFC8448HelloRetry.serverHello)
                + RFC8448HelloRetry.serverFlightRecord
        )
        #expect(server.state == .expectingClientFinished)
        // The client Finished is not printed by the trace, but every secret it depends on
        // is — reconstruct it from the published client handshake traffic secret and the
        // running transcript, seal it under the published client handshake keys, and the
        // machine must accept it.
        var transcript = TLSTranscriptHash(.sha256)
        transcript.append(RFC8448HelloRetry.clientHello1)
        transcript.collapseForHelloRetry()
        transcript.append(RFC8448HelloRetry.helloRetryRequest)
        transcript.append(RFC8448HelloRetry.clientHello2)
        transcript.append(RFC8448HelloRetry.serverHello)
        transcript.append(RFC8448HelloRetry.serverFlight)
        let clientSecret = SymmetricKey(
            data: RFC8448HelloRetry.clientHandshakeTrafficSecret
        )
        let finished = TLSFinishedCodec.finished(
            verifyData: TLSKeySchedule(hash: .sha256)
                .finishedVerifyData(
                    trafficSecret: clientSecret, transcriptHash: transcript.currentHash
                )
        )
        var sealer = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: clientSecret)
        var wire: [UInt8] = []
        try sealer.seal(type: .handshake, fragment: finished[...], into: &wire)
        events = try await server.receive(wire)
        guard case .handshakeCompleted(let negotiated) = events.first else {
            Issue.record("expected completion, got \(events)")
            return
        }
        #expect(negotiated.usedHelloRetry)
        #expect(negotiated.group == .secp256r1)
        #expect(negotiated.cipherSuite == .aes128GcmSha256)
        #expect(server.state == .connected)
    }

    @Test("the cookie slice fixture matches the §4.2.2 layout")
    func cookieSliceMatchesLayout() throws {
        // Parse the HRR fixture's extension block and confirm the cookie slice offsets.
        let body = RFC8448HelloRetry.helloRetryRequest[4...]
        var reader = TLSHandshakeReader(body)
        _ = try reader.u16("version")
        _ = try reader.slice(32, "random")
        _ = try reader.vector8("echo")
        _ = try reader.u16("suite")
        _ = try reader.byte("compression")
        var extensions = TLSHandshakeReader(try reader.vector16("extensions"))
        var cookie: [UInt8] = []
        while !extensions.isAtEnd {
            let type = try extensions.u16("type")
            var data = TLSHandshakeReader(try extensions.vector16("data"))
            if type == TLSExtensionType.cookie.rawValue {
                cookie = [UInt8](try data.vector16("cookie"))
            }
        }
        #expect(cookie == Self.traceCookie)
    }
}
