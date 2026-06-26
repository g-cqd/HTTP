//
//  ClientCertStampTests.swift
//  HTTPServerTests
//
//  G3 server stamp: the HTTP/1 dispatch path asserts the verified mutual-TLS client-certificate
//  subject (`TransportConnection.tlsPeerSubject`) onto the request as the server-controlled
//  `X-Client-Cert-Subject`, stripping any inbound value so a handler only ever sees a subject the
//  server itself verified — the same server-asserted-header pattern as `RequestIDMiddleware` /
//  `SessionMiddleware`. Driven through the real `serve` pipeline over a `FakeConnection` carrying an
//  injected subject, so the read → parse → stamp → respond path is exercised without sockets.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — mutual-TLS client-cert subject stamping")
struct ClientCertStampTests {
    /// Serves one request over a TLS HTTP/1.1 `FakeConnection` reporting `tlsPeerSubject`, returning
    /// the response wire bytes as a string.
    private func serve(
        request: String,
        tlsPeerSubject: String?,
        responder: any HTTPResponder
    ) async -> String {
        let connection = FakeConnection(
            id: TransportConnectionID(1),
            negotiatedApplicationProtocol: "http/1.1",
            isSecure: true,
            tlsPeerSubject: tlsPeerSubject,
            inbound: Array(request.utf8)
        )
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)
        return String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
    }

    /// A responder echoing the stamped `X-Client-Cert-Subject` the handler sees (or `<none>`).
    private func echoSubjectResponder() -> any HTTPResponder {
        ClosureResponder { request, _ in
            let subject = request.headerFields[.xClientCertSubject] ?? "<none>"
            return ServerResponse(HTTPResponse(status: .ok), body: Array(subject.utf8))
        }
    }

    @Test("stamps the verified client-certificate subject as a server-asserted header")
    func stampsVerifiedSubject() async {
        let wire = await serve(
            request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            tlsPeerSubject: "svc-a",
            responder: echoSubjectResponder()
        )
        #expect(wire.hasSuffix("\r\n\r\nsvc-a"))
    }

    @Test("strips a spoofed inbound subject when no client certificate was presented")
    func stripsSpoofWithoutClientCertificate() async {
        let wire = await serve(
            request: "GET / HTTP/1.1\r\nHost: x\r\nX-Client-Cert-Subject: attacker\r\n\r\n",
            tlsPeerSubject: nil,
            responder: echoSubjectResponder()
        )
        // The spoof was stripped — the handler sees no client-cert subject.
        #expect(wire.hasSuffix("\r\n\r\n<none>"))
        #expect(!wire.contains("attacker"))
    }

    @Test("a verified subject replaces any spoofed inbound value (never trusted from the wire)")
    func verifiedSubjectReplacesSpoof() async {
        let wire = await serve(
            request: "GET / HTTP/1.1\r\nHost: x\r\nX-Client-Cert-Subject: attacker\r\n\r\n",
            tlsPeerSubject: "svc-a",
            responder: echoSubjectResponder()
        )
        #expect(wire.hasSuffix("\r\n\r\nsvc-a"))
        #expect(!wire.contains("attacker"))
    }

    @Test("a subject containing CR/LF cannot inject a header line (CWE-93)")
    func rejectsHeaderInjectingSubject() async {
        let wire = await serve(
            request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            tlsPeerSubject: "evil\r\nX-Injected: pwned",
            responder: echoSubjectResponder()
        )
        // The CRLF-bearing subject fails `field-value` validation, so it is dropped rather than
        // forged into the request: the handler sees no subject and no injected line reaches the wire.
        #expect(wire.hasSuffix("\r\n\r\n<none>"))
        #expect(!wire.contains("X-Injected"))
    }
}
