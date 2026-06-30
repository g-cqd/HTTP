//
//  SessionMiddlewareTests.swift
//  HTTPServerTests
//
//  Signed-cookie sessions: issuing a signed cookie when none is present, continuing a valid session
//  without re-issuing, and rejecting a tampered cookie (a fresh session is issued and the tampered id
//  is never trusted). The echo responder reflects the request headers so a test can see the verified
//  X-Session-ID asserted onto the request.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — signed-cookie sessions")
struct SessionMiddlewareTests {
    private let key: [UInt8] = Array("test-session-key-0123456789abcdef".utf8)

    private let echo = ClosureResponder { request, _, _ in
        ServerResponse(HTTPResponse(status: .ok, headerFields: request.headerFields))
    }

    private func middleware(
        generate: @escaping @Sendable () -> String = { "sid-1" }
    ) -> SessionMiddleware {
        SessionMiddleware(key: key, isSecure: false, generate: generate)
    }

    private func request(cookie: String? = nil) -> HTTPRequest {
        var fields = HTTPFields()
        if let cookie { _ = fields.append(cookie, for: .cookie) }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }

    @Test("issues a signed session cookie when none is present")
    func issuesCookie() async {
        let response = await middleware().respond(to: request(), body: [], next: echo)
        let setCookie = response.head.headerFields[.setCookie] ?? ""
        #expect(setCookie.hasPrefix("session=sid-1."))  // <id>.<signature>
        #expect(setCookie.contains("HttpOnly"))
        // The verified id was asserted onto the request (and echoed back here).
        #expect(response.head.headerFields[.xSessionID] == "sid-1")
    }

    @Test("a valid signed cookie continues the session without re-issuing")
    func continuesSession() async {
        let issued = await middleware().respond(to: request(), body: [], next: echo)
        // Resend just the `session=<id>.<sig>` pair (drop the cookie attributes).
        let signed = String((issued.head.headerFields[.setCookie] ?? "").prefix { $0 != ";" })
        let response = await middleware().respond(to: request(cookie: signed), body: [], next: echo)
        #expect(response.head.headerFields[.setCookie] == nil)  // no new cookie issued
        #expect(response.head.headerFields[.xSessionID] == "sid-1")
    }

    @Test("a tampered cookie is rejected: a fresh session is issued, the tampered id not trusted")
    func rejectsTampered() async {
        let tampered = request(cookie: "session=evil.AAAA")
        let response = await middleware { "fresh" }.respond(to: tampered, body: [], next: echo)
        #expect(response.head.headerFields[.setCookie]?.hasPrefix("session=fresh.") == true)
        #expect(response.head.headerFields[.xSessionID] == "fresh")  // never "evil"
    }
}
