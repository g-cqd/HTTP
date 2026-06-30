//
//  ClientCertSubjectTests.swift
//  HTTPServerTests
//
//  G3 — the verified mutual-TLS client-certificate subject reaches handlers through the request
//  context (`RequestContext.connection.tlsPeerSubject`), captured from the TLS handshake by the
//  transport. This replaces the former `X-Client-Cert-Subject` request-header stamp: the subject is
//  now a server-asserted *value*, never a header derived from the wire — so a client cannot spoof it,
//  and a hostile subject cannot inject a header line (CWE-93) because there is no header to inject.
//  Driven through the real `serve` pipeline over a `FakeConnection` carrying an injected subject, so
//  the read → parse → respond path is exercised without sockets.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — mutual-TLS client-cert subject via RequestContext")
struct ClientCertSubjectTests {
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

    /// A responder echoing the verified client-cert subject the handler reads from the context.
    private func echoSubjectResponder() -> any HTTPResponder {
        ClosureResponder { _, _, context in
            let subject = context.connection.tlsPeerSubject ?? "<none>"
            return ServerResponse(HTTPResponse(status: .ok), body: Array(subject.utf8))
        }
    }

    @Test("delivers the verified client-certificate subject through the request context")
    func deliversVerifiedSubject() async {
        let wire = await serve(
            request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            tlsPeerSubject: "svc-a",
            responder: echoSubjectResponder()
        )
        #expect(wire.hasSuffix("\r\n\r\nsvc-a"))
    }

    @Test("no subject reaches the handler when no client certificate was presented")
    func noSubjectWithoutClientCertificate() async {
        let wire = await serve(
            request: "GET / HTTP/1.1\r\nHost: x\r\nX-Client-Cert-Subject: attacker\r\n\r\n",
            tlsPeerSubject: nil,
            responder: echoSubjectResponder()
        )
        // The context subject is nil (no client certificate); the spoofed inbound header is not a
        // source of truth, so the handler reads no subject.
        #expect(wire.hasSuffix("\r\n\r\n<none>"))
        #expect(!wire.contains("attacker"))
    }

    @Test("the subject comes from the verified connection, never a spoofed inbound header")
    func verifiedSubjectNotInboundHeader() async {
        let wire = await serve(
            request: "GET / HTTP/1.1\r\nHost: x\r\nX-Client-Cert-Subject: attacker\r\n\r\n",
            tlsPeerSubject: "svc-a",
            responder: echoSubjectResponder()
        )
        #expect(wire.hasSuffix("\r\n\r\nsvc-a"))
        #expect(!wire.contains("attacker"))
    }

    @Test("the subject is delivered as a value, so a CR/LF subject injects no header (CWE-93)")
    func subjectDeliveredAsValueNotHeader() async {
        // A hostile certificate whose subject embeds CR/LF used to risk header injection when the
        // server stamped it onto the request; the subject is now a context value the server never
        // stamps, so it cannot forge a header. The handler receives it verbatim (echoed into the body).
        let wire = await serve(
            request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            tlsPeerSubject: "evil\r\nX-Injected: pwned",
            responder: echoSubjectResponder()
        )
        // The response is one well-formed message; the CR/LF subject is confined to the body (after the
        // header terminator), never promoted to a header line in the head.
        #expect(wire.hasPrefix("HTTP/1.1 200"))
        #expect(wire.hasSuffix("\r\n\r\nevil\r\nX-Injected: pwned"))
    }
}
