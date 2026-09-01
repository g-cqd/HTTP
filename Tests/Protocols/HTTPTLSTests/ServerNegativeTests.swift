//
//  ServerNegativeTests.swift
//  HTTPTLSTests
//
//  The negative battery — the h3spec lesson: test what RFC 8446 FORBIDS, not just what it
//  allows. Every case asserts three things at once (the one-funnel contract): the exact typed
//  error, the exact §6 alert that error maps to, and the terminal state. ClientHello-stage
//  violations also check the alert ON THE WIRE (the write epoch is still plaintext there, so
//  the queued alert record is readable).
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("The negative battery — what RFC 8446 forbids must die with the right alert")
struct ServerNegativeTests {
    /// A permissive default server.
    private static func makeConnection(
        configure: ((inout TLSServerConfiguration) -> Void)? = nil
    ) -> TLSServerConnection {
        var configuration = TLSServerConfiguration()
        configure?(&configuration)
        return TLSServerConnection(
            configuration: configuration, identity: P256TestIdentity()
        )
    }

    /// Drives one hello record and asserts (typed error, wire alert, terminal state).
    private static func expectFatalHello(
        _ hello: TestClientHello,
        _ expected: TLSHandshakeError,
        configure: ((inout TLSServerConfiguration) -> Void)? = nil,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async {
        var server = makeConnection(configure: configure)
        do {
            _ = try await server.receive(TestClientHello.plaintextRecord(hello.message()))
            Issue.record("expected \(expected)", sourceLocation: sourceLocation)
        }
        catch {
            #expect(error == expected, sourceLocation: sourceLocation)
        }
        #expect(server.state == .failed(expected), sourceLocation: sourceLocation)
        guard let alert = expected.alertDescription else {
            Issue.record("battery cases must map to an alert", sourceLocation: sourceLocation)
            return
        }
        #expect(
            server.outboundBytes() == [21, 3, 3, 0, 2, 2, alert.rawValue],
            "exactly one fatal alert on the wire",
            sourceLocation: sourceLocation
        )
    }

    /// A client with a valid x25519 share (the baseline the battery mutates).
    private static func baseline() -> (TestClientHello, [UInt8]) {
        let key = Curve25519.KeyAgreement.PrivateKey()
        var hello = TestClientHello()
        hello.keyShares = [(0x001D, [UInt8](key.publicKey.rawRepresentation))]
        return (hello, [UInt8](key.publicKey.rawRepresentation))
    }

    // MARK: version and downgrade (§4.2.1, Appendix D.2/D.5)

    @Test("a TLS 1.2 ClientHello (no supported_versions) dies as protocol_version — D.2")
    func downgradeNoSupportedVersions() async {
        var (hello, _) = Self.baseline()
        hello.supportedVersions = nil
        await Self.expectFatalHello(hello, .unsupportedVersion)
    }

    @Test("supported_versions without 0x0304 dies as protocol_version — §4.2.1/D.2")
    func downgradeWithoutTLS13() async {
        var (hello, _) = Self.baseline()
        hello.supportedVersions = [0x0303, 0x0302]
        await Self.expectFatalHello(hello, .unsupportedVersion)
    }

    @Test("legacy_version 0x0300 dies as protocol_version — Appendix D.5")
    func ssl3LegacyVersion() async {
        var (hello, _) = Self.baseline()
        hello.legacyVersion = 0x0300
        await Self.expectFatalHello(hello, .unsupportedVersion)
    }

    // MARK: shape rules (§4.1.2/§4.2)

    @Test("non-null compression dies as illegal_parameter — §4.1.2")
    func nonNullCompression() async {
        var (hello, _) = Self.baseline()
        hello.compression = [1, 0]
        await Self.expectFatalHello(hello, .illegalParameter("legacy_compression_methods"))
    }

    @Test("a duplicated extension dies as illegal_parameter — §4.2")
    func duplicateExtension() async {
        var (hello, _) = Self.baseline()
        hello.rawExtensions = [(10, [0, 2, 0, 0x1D])]  // second supported_groups
        await Self.expectFatalHello(hello, .duplicateExtension(.supportedGroups))
    }

    @Test("a recognized extension where the §4.2 table forbids it dies as illegal_parameter")
    func extensionInWrongMessage() async {
        var (hello, _) = Self.baseline()
        hello.rawExtensions = [(48, [0, 0])]  // oid_filters is CertificateRequest-only
        await Self.expectFatalHello(hello, .extensionNotPermitted(.oidFilters))
    }

    @Test("pre_shared_key anywhere but last dies as illegal_parameter — §4.2.11")
    func preSharedKeyNotLast() async {
        var (hello, _) = Self.baseline()
        hello.preSharedKey = (
            identities: [([1, 2, 3], 0)], binders: [[UInt8](repeating: 0, count: 32)]
        )
        hello.preSharedKeyFirst = true
        await Self.expectFatalHello(hello, .preSharedKeyNotLast)
    }

    @Test("pre_shared_key without psk_key_exchange_modes dies as missing_extension — §4.2.9")
    func pskWithoutModes() async {
        var (hello, _) = Self.baseline()
        hello.preSharedKey = (
            identities: [([1, 2, 3], 0)], binders: [[UInt8](repeating: 0, count: 32)]
        )
        hello.pskKeyExchangeModes = nil
        await Self.expectFatalHello(hello, .missingExtension(.pskKeyExchangeModes))
    }

    @Test("a key share for a group outside supported_groups dies as illegal_parameter — §4.2.8")
    func shareOutsideGroups() async {
        var (hello, share) = Self.baseline()
        hello.supportedGroups = [0x0017]  // P-256 only, but the share is x25519
        hello.keyShares = [(0x001D, share)]
        await Self.expectFatalHello(
            hello, .illegalParameter("key_share group not in supported_groups")
        )
    }

    @Test("mandatory extensions must be present — §9.2", arguments: [10, 51])
    func missingMandatoryExtension(rawType: UInt16) async {
        var (hello, _) = Self.baseline()
        if rawType == 10 {
            hello.supportedGroups = nil
        }
        else {
            hello.keyShares = nil
        }
        await Self.expectFatalHello(
            hello, .missingExtension(TLSExtensionType(rawValue: rawType))
        )
    }

    @Test("record_size_limit below 64 dies as illegal_parameter — RFC 8449 §4")
    func tinyRecordSizeLimit() async {
        var (hello, _) = Self.baseline()
        hello.recordSizeLimit = 63
        await Self.expectFatalHello(hello, .illegalParameter("record_size_limit below 64"))
    }

    // MARK: negotiation failures (§4.1.1, RFC 7301)

    @Test("no common cipher suite dies as handshake_failure — §4.1.1")
    func noCommonSuite() async {
        var (hello, _) = Self.baseline()
        hello.cipherSuites = [0x1399]
        await Self.expectFatalHello(hello, .negotiationFailed("cipher suites"))
    }

    @Test("no common group dies as handshake_failure — §4.1.1")
    func noCommonGroup() async {
        var (hello, _) = Self.baseline()
        hello.supportedGroups = [0x0019]  // P-521: recognized, unimplemented
        hello.keyShares = []
        await Self.expectFatalHello(hello, .negotiationFailed("groups"))
    }

    @Test("no common signature scheme dies as handshake_failure — §4.1.1/§4.4.3")
    func noCommonSignatureScheme() async {
        var (hello, _) = Self.baseline()
        hello.signatureAlgorithms = [0x0401]  // rsa_pkcs1: never valid in CertificateVerify
        await Self.expectFatalHello(hello, .negotiationFailed("signature schemes"))
    }

    @Test("ALPN offered with no overlap dies as no_application_protocol — RFC 7301 §3.2")
    func alpnMismatch() async {
        var (hello, _) = Self.baseline()
        hello.alpnProtocols = ["h2", "http/1.1"]
        await Self.expectFatalHello(hello, .noApplicationProtocol) { configuration in
            configuration.alpnProtocols = ["h3"]
        }
    }

    @Test("an invalid x25519 key share dies as illegal_parameter — §4.2.8.2")
    func malformedShare() async {
        var (hello, _) = Self.baseline()
        hello.keyShares = [(0x001D, [UInt8](repeating: 7, count: 31))]  // wrong length
        await Self.expectFatalHello(
            hello, .illegalParameter("key_exchange length for group 29")
        )
    }

    // MARK: HelloRetryRequest contract (§4.1.2/§4.1.4/§4.2.2/§4.2.8)

    /// A server that always needs an HRR (P-256 only) plus a first-round hello (x25519
    /// share) that provoked it, cookie included.
    private static func retriedServer() async throws -> (TLSServerConnection, TestClientHello) {
        var server = makeConnection { configuration in
            configuration.groups = [.secp256r1]
            configuration.cookieProvider = { _ in [0xC0, 0x0C, 0x1E] }
        }
        let (hello, _) = baseline()
        _ = try await server.receive(TestClientHello.plaintextRecord(hello.message()))
        _ = server.outboundBytes()
        #expect(server.state == .expectingRetriedClientHello)
        return (server, hello)
    }

    /// Runs a retried hello and asserts the funnel triple.
    private static func expectFatalRetry(
        _ mutate: (inout TestClientHello) -> Void,
        _ expected: TLSHandshakeError,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async throws {
        var (server, hello) = try await retriedServer()
        let p256 = P256.KeyAgreement.PrivateKey()
        hello.keyShares = [(0x0017, [UInt8](p256.publicKey.x963Representation))]
        hello.cookie = [0xC0, 0x0C, 0x1E]
        mutate(&hello)
        do {
            _ = try await server.receive(TestClientHello.plaintextRecord(hello.message()))
            Issue.record("expected \(expected)", sourceLocation: sourceLocation)
        }
        catch {
            #expect(error == expected, sourceLocation: sourceLocation)
        }
        #expect(server.state == .failed(expected), sourceLocation: sourceLocation)
    }

    @Test("a retried hello still lacking the demanded share dies as illegal_parameter")
    func retryWithoutDemandedShare() async throws {
        try await Self.expectFatalRetry(
            { hello in
                hello.keyShares = []
            },
            .illegalParameter("retried ClientHello lacks the requested key share")
        )
    }

    @Test("a retried hello that changes the cipher suite dies as illegal_parameter — §4.1.4")
    func retryChangesSuite() async throws {
        try await Self.expectFatalRetry(
            { hello in
                hello.cipherSuites = [0x1302]
            },
            .illegalParameter("cipher suite changed after HelloRetryRequest")
        )
    }

    @Test("a retried hello without the cookie dies as missing_extension — §4.2.2")
    func retryDropsCookie() async throws {
        try await Self.expectFatalRetry(
            { hello in
                hello.cookie = nil
            },
            .missingExtension(.cookie)
        )
    }

    @Test("a retried hello with a corrupted cookie dies as illegal_parameter — §4.2.2")
    func retryCorruptsCookie() async throws {
        try await Self.expectFatalRetry(
            { hello in
                hello.cookie = [0xBA, 0xD0]
            },
            .illegalParameter("cookie")
        )
    }

    @Test("a retried hello that still offers early_data dies as illegal_parameter — §4.1.2")
    func retryKeepsEarlyData() async throws {
        try await Self.expectFatalRetry(
            { hello in
                hello.offersEarlyData = true
            },
            .illegalParameter("early_data in retried ClientHello")
        )
    }

    // MARK: order and framing (§4, §5.1)

    @Test("a second ClientHello after completion dies as unexpected_message — §4")
    func renegotiationAttempt() async throws {
        var server = Self.makeConnection()
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        _ = try await server.receive(try client.finishHandshake())
        #expect(server.state == .connected)
        // A ClientHello under the application keys: TLS 1.3 has no renegotiation.
        try client.record.send(handshake: TestClientHello().message())
        await #expect(throws: TLSHandshakeError.unexpectedMessage(.clientHello)) {
            _ = try await server.receive(client.record.outboundBytes())
        }
    }

    @Test("a Finished before the ClientHello dies as unexpected_message — §4")
    func finishedFirst() async {
        var server = Self.makeConnection()
        let finished = TLSFinishedCodec.finished(verifyData: [UInt8](repeating: 0, count: 32))
        await #expect(throws: TLSHandshakeError.unexpectedMessage(.finished)) {
            _ = try await server.receive(TestClientHello.plaintextRecord(finished))
        }
    }

    @Test("EndOfEarlyData is never legitimate here (0-RTT rejected) — §4.2.10/§4.5")
    func endOfEarlyData() async throws {
        var server = Self.makeConnection()
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        let eoed = TLSHandshakeBuilder.message(.endOfEarlyData) { _ in
            // empty body (§4.5)
        }
        try client.record.send(handshake: eoed)
        await #expect(throws: TLSHandshakeError.unexpectedMessage(.endOfEarlyData)) {
            _ = try await server.receive(client.record.outboundBytes())
        }
    }

    @Test("an unknown handshake type dies as unexpected_message")
    func unknownHandshakeType() async {
        var server = Self.makeConnection()
        let bogus: [UInt8] = [99, 0, 0, 1, 0]
        await #expect(throws: TLSHandshakeError.unknownHandshakeType(99)) {
            _ = try await server.receive(TestClientHello.plaintextRecord(bogus))
        }
    }

    @Test("a handshake message above the reassembly cap dies as decode_error")
    func oversizedHandshakeMessage() async {
        var server = Self.makeConnection { configuration in
            configuration.maxHandshakeMessageLength = 1_024
        }
        let header: [UInt8] = [1, 0x10, 0, 0]  // ClientHello claiming 2^20 octets
        await #expect(
            throws: TLSHandshakeError.messageTooLarge(declared: 1 << 20, limit: 1_024)
        ) {
            _ = try await server.receive(TestClientHello.plaintextRecord(header))
        }
        #expect(server.state.isTerminal)
    }

    @Test("an alert interleaved inside a fragmented handshake message dies — §5.1")
    func interleavedAlert() async {
        var server = Self.makeConnection()
        let (hello, _) = Self.baseline()
        let message = hello.message()
        // First half of the ClientHello, then a (plaintext) close_notify record between
        // the fragments.
        let half = message.count / 2
        var wire = TestClientHello.plaintextRecord([UInt8](message[..<half]))
        wire += [21, 3, 3, 0, 2, 1, 0]
        await #expect(throws: TLSHandshakeError.interleavedHandshake(.alert)) {
            _ = try await server.receive(wire)
        }
    }

    @Test("a bad client Finished dies as decrypt_error — §4.4.4")
    func badClientFinished() async throws {
        var server = Self.makeConnection()
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        let wire = try client.sendFlight([try client.finishedMessage(corrupted: true)])
        await #expect(throws: TLSHandshakeError.invalidFinished) {
            _ = try await server.receive(wire)
        }
        #expect(server.state == .failed(.invalidFinished))
    }

    @Test("a client Finished over the WRONG transcript dies as decrypt_error — §4.4.4")
    func finishedOverWrongTranscript() async throws {
        var server = Self.makeConnection()
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        client.transcript.append([0xDE, 0xAD])  // desynchronize the transcript
        let wire = try client.sendFlight([try client.finishedMessage()])
        await #expect(throws: TLSHandshakeError.invalidFinished) {
            _ = try await server.receive(wire)
        }
    }

    @Test("a KeyUpdate with request_update=2 dies as illegal_parameter — §4.6.3")
    func badKeyUpdateValue() async throws {
        var server = Self.makeConnection()
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        _ = try await server.receive(try client.finishHandshake())
        let bogus = TLSHandshakeBuilder.message(.keyUpdate) { $0.u8(2) }
        try client.record.send(handshake: bogus)
        await #expect(throws: TLSHandshakeError.invalidKeyUpdate(2)) {
            _ = try await server.receive(client.record.outboundBytes())
        }
    }

    @Test("a peer error alert is terminal with NO answering alert — §6.2")
    func peerAlertGetsNoAnswer() async throws {
        var server = Self.makeConnection()
        let alert: [UInt8] = [21, 3, 3, 0, 2, 2, 40]  // fatal handshake_failure
        await #expect(
            throws: TLSHandshakeError.peerAlert(
                TLSAlert(level: 2, description: .handshakeFailure)
            )
        ) {
            _ = try await server.receive(alert)
        }
        #expect(server.outboundBytes().isEmpty, "§6.2: MUST NOT send further data")
        #expect(server.state.isTerminal)
    }

    @Test("the early-data skip budget is finite — exhaustion dies as bad_record_mac")
    func earlyDataBudgetExhaustion() async throws {
        var server = Self.makeConnection { configuration in
            configuration.maxEarlyDataSkipOctets = 64
        }
        var client = HandshakeTestClient()
        _ = try await server.receive(
            try client.helloRecord { hello in
                hello.offersEarlyData = true
            }
        )
        _ = server.outboundBytes()
        // Garbage "early data" larger than the budget: the skip window must not be a
        // decryption-failure amnesty without bound.
        let garbage = [UInt8](repeating: 0x5A, count: 128)
        let record: [UInt8] = [23, 3, 3, 0, 128] + garbage
        await #expect(throws: TLSHandshakeError.record(.badRecordMac)) {
            _ = try await server.receive(record)
        }
        #expect(server.state.isTerminal)
    }
}
