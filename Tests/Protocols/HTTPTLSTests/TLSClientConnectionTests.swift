//
//  TLSClientConnectionTests.swift
//  HTTPTLSTests
//
//  RED→GREEN driver for the sans-I/O RFC 8446 §4 TLS 1.3 client state machine (`TLSClientConnection`),
//  paired back-to-back against `TLSServerConnection` across X25519 + P-256, HelloRetryRequest,
//  ECDSA + RSA-PSS server certificates, SAN hostname verification, wrong-host rejection, and
//  post-handshake NewSessionTicket / KeyUpdate / bidirectional application data + close_notify.
//

import Crypto
import HTTPTLSRSA
import HTTPTransport
import Testing

@testable internal import HTTPTLS

@Suite("RFC 8446 §4 — sans-I/O TLS 1.3 client connection")
struct TLSClientConnectionTests {
    private func pump(
        client: inout TLSClientConnection,
        server: inout TLSServerConnection
    ) async throws -> (clientEvents: [TLSClientEvent], serverEvents: [TLSServerEvent]) {
        var clientEvents: [TLSClientEvent] = []
        var serverEvents: [TLSServerEvent] = []
        for _ in 0 ..< 8 {
            let c2s = client.outboundBytes()
            if !c2s.isEmpty {
                serverEvents.append(contentsOf: try await server.receive(c2s))
            }
            let s2c = server.outboundBytes()
            if !s2c.isEmpty {
                clientEvents.append(contentsOf: try await client.receive(s2c))
            }
            if c2s.isEmpty, s2c.isEmpty {
                break
            }
        }
        return (clientEvents, serverEvents)
    }

    @Test(
        "completes a 1-RTT X25519 + ECDSA handshake with SAN validation, ALPN, and application data"
    )
    func oneRttHandshakeAndAppData() async throws {
        let ca = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(
            commonName: "developer.apple.com",
            by: ca,
            sans: ["developer.apple.com"]
        )
        var serverConfig = TLSServerConfiguration()
        serverConfig.alpnProtocols = ["http/1.1"]
        let ticketKey = try #require(
            TLSTicketKey(
                name: [UInt8](repeating: 1, count: 8),
                secret: SymmetricKey(size: .bits256)
            )
        )
        serverConfig.ticketVault = TLSStatelessTicketVault(keys: [ticketKey])
        var server = TLSServerConnection(
            configuration: serverConfig,
            identity: try TLSCertificateIdentity(
                certificateChainDER: [leaf.der],
                signer: TLSPrivateKey.p256(leaf.key)
            )
        )

        var clientConfig = TLSClientConfiguration(
            serverName: "developer.apple.com",
            trustRootsDER: [ca.der]
        )
        clientConfig.alpnProtocols = ["http/1.1"]
        var client = try TLSClientConnection(configuration: clientConfig)
        try client.start()

        let (cEvents, sEvents) = try await pump(client: &client, server: &server)
        #expect(
            cEvents.contains {
                if case .handshakeCompleted(let params) = $0 {
                    return params.alpnProtocol == "http/1.1" && !params.usedHelloRetry
                }
                return false
            })
        #expect(
            sEvents.contains {
                if case .handshakeCompleted(let params) = $0 {
                    return params.serverName == "developer.apple.com"
                }
                return false
            })

        // Client -> Server -> Client application data + NewSessionTicket + KeyUpdate + close_notify.
        try server.issueSessionTicket()
        try client.send(applicationData: Array("GET / HTTP/1.1\r\n\r\n".utf8))
        let (_, sApp) = try await pump(client: &client, server: &server)
        #expect(sApp == [.applicationData(Array("GET / HTTP/1.1\r\n\r\n".utf8))])

        try server.requestKeyUpdate(askPeerToUpdate: true)
        try server.send(applicationData: Array("HTTP/1.1 200 OK\r\n\r\n".utf8))
        let (cApp1, _) = try await pump(client: &client, server: &server)
        #expect(cApp1.contains(.applicationData(Array("HTTP/1.1 200 OK\r\n\r\n".utf8))))

        server.close()
        let (cApp2, _) = try await pump(client: &client, server: &server)
        #expect(cApp2.contains(.peerClosed))
    }

    @Test(
        "negotiates HelloRetryRequest when server demands P-256 and client initially shared X25519"
    )
    func helloRetryRequestRound() async throws {
        let ca = try TestPKI.certificateAuthority()
        let leaf = try TestPKI.issued(commonName: "swift.org", by: ca, sans: ["swift.org"])
        var serverConfig = TLSServerConfiguration()
        serverConfig.groups = [.secp256r1]  // force HRR
        serverConfig.cookieProvider = { Array($0.prefix(16)) }
        var server = TLSServerConnection(
            configuration: serverConfig,
            identity: try TLSCertificateIdentity(
                certificateChainDER: [leaf.der],
                signer: TLSPrivateKey.p256(leaf.key)
            )
        )

        let clientConfig = TLSClientConfiguration(
            serverName: "swift.org",
            trustRootsDER: [ca.der]
        )
        var client = try TLSClientConnection(configuration: clientConfig)
        try client.start()

        let (cEvents, _) = try await pump(client: &client, server: &server)
        #expect(
            cEvents.contains {
                if case .handshakeCompleted(let params) = $0 {
                    return params.usedHelloRetry && params.group == .secp256r1
                }
                return false
            })
    }

    @Test("verifies RSA-PSS server certificates via TLSRSACertificateVerifier")
    func rsaServerCertificateVerifies() async throws {
        let dev = try #require(try? DevTLSIdentity.selfSignedPEM())
        var server = TLSServerConnection(
            configuration: TLSServerConfiguration(),
            identity: try TLSCertificateIdentity(
                certificateChainPEM: dev.certificatePEM,
                signer: TLSRSAIdentitySigner(privateKeyPEM: dev.privateKeyPEM)
            )
        )
        let certDER = try #require(
            try TLSCertificateIdentity(
                certificateChainPEM: dev.certificatePEM,
                signer: TLSRSAIdentitySigner(privateKeyPEM: dev.privateKeyPEM)
            )
            .certificateChainDER.first
        )
        var clientConfig = TLSClientConfiguration(
            serverName: nil,
            trustRootsDER: [certDER]
        )
        clientConfig.certificateVerifier = TLSRSACertificateVerifier()
        var client = try TLSClientConnection(configuration: clientConfig)
        try client.start()

        let (cEvents, _) = try await pump(client: &client, server: &server)
        #expect(
            cEvents.contains {
                if case .handshakeCompleted = $0 {
                    return true
                }
                return false
            })
    }

    @Test("rejects a certificate whose SAN does not match serverName and rejects untrusted roots")
    func rejectsMismatchedHostnameAndUntrustedCA() async throws {
        let ca = try TestPKI.certificateAuthority()
        let otherCA = try TestPKI.certificateAuthority(commonName: "Other CA")
        let leaf = try TestPKI.issued(commonName: "evil.example", by: ca, sans: ["evil.example"])

        var server1 = TLSServerConnection(
            configuration: TLSServerConfiguration(),
            identity: try TLSCertificateIdentity(
                certificateChainDER: [leaf.der],
                signer: TLSPrivateKey.p256(leaf.key)
            )
        )
        var wrongHostClient = try TLSClientConnection(
            configuration: TLSClientConfiguration(
                serverName: "developer.apple.com",
                trustRootsDER: [ca.der]
            )
        )
        try wrongHostClient.start()
        await #expect(throws: TLSHandshakeError.self) {
            _ = try await pump(client: &wrongHostClient, server: &server1)
        }

        var server2 = TLSServerConnection(
            configuration: TLSServerConfiguration(),
            identity: try TLSCertificateIdentity(
                certificateChainDER: [leaf.der],
                signer: TLSPrivateKey.p256(leaf.key)
            )
        )
        var untrustedClient = try TLSClientConnection(
            configuration: TLSClientConfiguration(
                serverName: "evil.example",
                trustRootsDER: [otherCA.der]
            )
        )
        try untrustedClient.start()
        await #expect(throws: TLSHandshakeError.self) {
            _ = try await pump(client: &untrustedClient, server: &server2)
        }
    }
}
