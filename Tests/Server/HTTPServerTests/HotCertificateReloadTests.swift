//
//  HotCertificateReloadTests.swift
//  HTTPServerTests
//
//  G4b — `HTTPServer.reloadCertificate` forwards to the transport's restart-based TLS reload. The real
//  loopback reload is gated at the transport layer (CertificateReloadTests); here we confirm the
//  server entry point delegates — observably, via the unsupported-backbone protocol default.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — hot certificate reload (G4b)")
struct HotCertificateReloadTests {
    @Test("reloadCertificate forwards to the transport (unsupported on the fake backbone)")
    func reloadCertificateDelegatesToTransport() async throws {
        let tls = try SharedDevTLSIdentity.value()
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        let unsupported = TransportError.unsupported(
            "TLS reload is unsupported by the fake backbone"
        )
        await #expect(throws: unsupported) {
            try await server.reloadCertificate(tls)
        }
    }
}
