//
//  ClientChainValidationTests.swift
//  HTTPTLSTests
//
//  Client-chain validation over the 3c trust seam (RFC 5280 §6, RFC 8446 §4.4.2.4) with a
//  swift-certificates-minted test PKI: a chain signed by the trusted CA passes; without
//  the CA in roots the handshake dies with `unknown_ca`; an expired leaf with
//  `certificate_expired`; a hostname-violating leaf (under the composed identity policy)
//  and a hook veto with `bad_certificate` — each alert read back from the WIRE by the
//  in-test client, and fail-closed under `.optional` too (§6.2 for every mapping).
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("Client chain validation — RFC 5280 §6 verdicts and their §6.2 alerts")
struct ClientChainValidationTests {
    /// A server requesting client certificates under `mode` with `validator` wired.
    private static func makeServer(
        mode: TLSClientAuthenticationMode = .required,
        validator: (any TLSClientChainValidator)?
    ) throws -> TLSServerConnection {
        let authority = try TestPKI.certificateAuthority(commonName: "Server CA")
        let leaf = try TestPKI.issued(commonName: "server.test", by: authority)
        var configuration = TLSServerConfiguration()
        configuration.clientAuthentication = mode
        configuration.clientChainValidator = validator
        return TLSServerConnection(
            configuration: configuration,
            identity: try TLSCertificateIdentity(
                certificateChainDER: [leaf.der], signer: TLSPrivateKey.p256(leaf.key)
            )
        )
    }

    /// Runs the full mTLS second flight for `chain` (leaf key `signingKey`); returns the
    /// server error (nil on success) and the alert the client read off the wire.
    private static func presentChain(
        server: inout TLSServerConnection,
        chain: [[UInt8]],
        signingKey: P256.Signing.PrivateKey
    ) async throws -> (failure: TLSHandshakeError?, alert: TLSAlert?) {
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        var wire = try client.sendFlight(
            [client.certificateMessage(chain: chain)], promote: false
        )
        wire += try client.sendFlight(
            [try client.certificateVerifyMessage(signingKey: signingKey)], promote: false
        )
        wire += try client.sendFlight([try client.finishedMessage()])
        do {
            _ = try await server.receive(wire)
            return (nil, nil)
        }
        catch {
            try client.absorb(server.outboundBytes())
            return (error, client.alerts.first)
        }
    }

    @Test("a chain signed by a trusted CA validates; the handshake completes")
    func trustedChainCompletes() async throws {
        let clientCA = try TestPKI.certificateAuthority(commonName: "Client CA")
        let clientLeaf = try TestPKI.issued(commonName: "client", by: clientCA)
        var server = try Self.makeServer(
            validator: try TLSX509ChainValidator(rootsDER: [clientCA.der])
        )
        let outcome = try await Self.presentChain(
            server: &server, chain: [clientLeaf.der], signingKey: clientLeaf.key
        )
        #expect(outcome.failure == nil)
        #expect(server.state == .connected)
        #expect(server.negotiated?.clientCertificateChainDER == [clientLeaf.der])
    }

    @Test("a leaf through a presented INTERMEDIATE validates to the pinned root")
    func intermediateChainCompletes() async throws {
        let root = try TestPKI.certificateAuthority(commonName: "Client Root")
        let intermediate = try TestPKI.issued(
            commonName: "Client Intermediate", by: root, isAuthority: true
        )
        let leaf = try TestPKI.issued(commonName: "client", by: intermediate)
        var server = try Self.makeServer(
            validator: try TLSX509ChainValidator(rootsDER: [root.der])
        )
        let outcome = try await Self.presentChain(
            server: &server, chain: [leaf.der, intermediate.der], signingKey: leaf.key
        )
        #expect(outcome.failure == nil)
        #expect(server.state == .connected)
    }

    @Test("a chain to an UNKNOWN CA dies with unknown_ca (§6.2)")
    func untrustedChainIsUnknownCA() async throws {
        let trustedCA = try TestPKI.certificateAuthority(commonName: "Trusted CA")
        let otherCA = try TestPKI.certificateAuthority(commonName: "Other CA")
        let leaf = try TestPKI.issued(commonName: "client", by: otherCA)
        var server = try Self.makeServer(
            validator: try TLSX509ChainValidator(rootsDER: [trustedCA.der])
        )
        let outcome = try await Self.presentChain(
            server: &server, chain: [leaf.der], signingKey: leaf.key
        )
        #expect(outcome.failure == .clientChainRejected(.untrustedRoot))
        #expect(outcome.alert == TLSAlert(level: TLSAlert.fatalLevel, description: .unknownCA))
    }

    @Test("an EXPIRED leaf dies with certificate_expired (§6.2)")
    func expiredLeafIsCertificateExpired() async throws {
        let clientCA = try TestPKI.certificateAuthority(commonName: "Client CA")
        let expired = try TestPKI.issued(
            commonName: "client",
            by: clientCA,
            notValidBeforeOffset: -7_200,
            notValidAfterOffset: -3_600
        )
        var server = try Self.makeServer(
            validator: try TLSX509ChainValidator(rootsDER: [clientCA.der])
        )
        let outcome = try await Self.presentChain(
            server: &server, chain: [expired.der], signingKey: expired.key
        )
        #expect(outcome.failure == .clientChainRejected(.expired))
        #expect(
            outcome.alert
                == TLSAlert(level: TLSAlert.fatalLevel, description: .certificateExpired)
        )
    }

    @Test("a hostname-violating leaf dies under the composed identity policy")
    func hostnameViolationRejected() async throws {
        let clientCA = try TestPKI.certificateAuthority(commonName: "Client CA")
        let leaf = try TestPKI.issued(
            commonName: "client", by: clientCA, sans: ["other.example"]
        )
        var server = try Self.makeServer(
            validator: try TLSX509ChainValidator(
                rootsDER: [clientCA.der], expectedHostname: "client.example"
            )
        )
        let outcome = try await Self.presentChain(
            server: &server, chain: [leaf.der], signingKey: leaf.key
        )
        guard case .clientChainRejected(.badCertificate) = outcome.failure else {
            Issue.record("expected a bad_certificate rejection, got \(outcome)")
            return
        }
        #expect(
            outcome.alert == TLSAlert(level: TLSAlert.fatalLevel, description: .badCertificate)
        )
    }

    @Test("fail closed under .optional too: present-but-unvalidatable aborts")
    func optionalModeStillFailsClosed() async throws {
        let trustedCA = try TestPKI.certificateAuthority(commonName: "Trusted CA")
        let otherCA = try TestPKI.certificateAuthority(commonName: "Other CA")
        let leaf = try TestPKI.issued(commonName: "client", by: otherCA)
        var server = try Self.makeServer(
            mode: .optional,
            validator: try TLSX509ChainValidator(rootsDER: [trustedCA.der])
        )
        let outcome = try await Self.presentChain(
            server: &server, chain: [leaf.der], signingKey: leaf.key
        )
        #expect(outcome.failure == .clientChainRejected(.untrustedRoot))
    }

    @Test(
        "a verifyPeer-style hook passes straight through; false is bad_certificate",
        arguments: [true, false])
    func verifyPeerHookAdapter(accepts: Bool) async throws {
        let clientCA = try TestPKI.certificateAuthority(commonName: "Client CA")
        let leaf = try TestPKI.issued(commonName: "client", by: clientCA)
        let expected = [leaf.der]
        var server = try Self.makeServer(
            validator: TLSVerifyPeerHookValidator { chain in accepts && chain == expected }
        )
        let outcome = try await Self.presentChain(
            server: &server, chain: [leaf.der], signingKey: leaf.key
        )
        if accepts {
            #expect(outcome.failure == nil)
            #expect(server.state == .connected)
        }
        else {
            guard case .clientChainRejected(.badCertificate) = outcome.failure else {
                Issue.record("expected a bad_certificate rejection, got \(outcome)")
                return
            }
            #expect(
                outcome.alert
                    == TLSAlert(level: TLSAlert.fatalLevel, description: .badCertificate)
            )
        }
    }

    @Test("nil validator keeps the 3b semantics: a signature-verified chain is accepted")
    func nilValidatorAcceptsPresentedChain() async throws {
        let anyCA = try TestPKI.certificateAuthority(commonName: "Any CA")
        let leaf = try TestPKI.issued(commonName: "client", by: anyCA)
        var server = try Self.makeServer(validator: nil)
        let outcome = try await Self.presentChain(
            server: &server, chain: [leaf.der], signingKey: leaf.key
        )
        #expect(outcome.failure == nil)
        #expect(server.state == .connected)
    }

    @Test("trust-root configuration fails at startup: empty and undecodable roots")
    func rootConfigurationFailsClosed() throws {
        #expect(throws: TLSX509ChainValidator.ConfigurationError.noTrustRoots) {
            _ = try TLSX509ChainValidator(rootsDER: [])
        }
        do {
            _ = try TLSX509ChainValidator(rootsDER: [[0xBA, 0xD0]])
            Issue.record("expected a configuration failure")
        }
        catch {
            guard case .undecodableTrustRoot(let index, _) = error else {
                Issue.record("expected undecodableTrustRoot, got \(error)")
                return
            }
            #expect(index == 0)
        }
    }
}
