//
//  SessionStoreMiddlewareTests.swift
//  HTTPServerTests
//
//  Phase 2.6 — SessionMiddleware backed by a server-side ``SessionStore``: a minted session is registered
//  and continues while live, a revoked session (logout) stops being accepted even though its cookie is
//  still HMAC-valid, and the stateless path (no store) is unchanged.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — server-side sessions (store)")
struct SessionStoreMiddlewareTests {
    private let key: [UInt8] = Array("test-session-key-0123456789abcdef".utf8)

    private let echo = ClosureResponder { request, _, _ in
        ServerResponse(HTTPResponse(status: .ok, headerFields: request.headerFields))
    }

    private func request(cookie: String? = nil) -> HTTPRequest {
        var fields = HTTPFields()
        if let cookie { _ = fields.append(cookie, for: .cookie) }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }

    /// The bare `session=<id>.<sig>` pair from a Set-Cookie (dropping the attributes), to resend.
    private func signedPair(_ response: ServerResponse) -> String {
        String((response.head.headerFields[.setCookie] ?? "").prefix { $0 != ";" })
    }

    @Test("a revoked session is rejected even with a valid cookie — logout works")
    func revokedSessionReissued() async {
        let store = InMemorySessionStore()
        let middleware = SessionMiddleware(
            key: key, isSecure: false, generate: { "sid-1" }, store: store
        )
        let issued = await middleware.respond(to: request(), body: [], next: echo)
        #expect(await store.validate("sid-1"))  // minted session was registered
        let signed = signedPair(issued)
        // While live, the cookie continues the session without re-issuing.
        let cont = await middleware.respond(to: request(cookie: signed), body: [], next: echo)
        #expect(cont.head.headerFields[.setCookie] == nil)
        // After revocation, the still-HMAC-valid cookie no longer continues — a fresh cookie is issued.
        await store.revoke("sid-1")
        let after = await middleware.respond(to: request(cookie: signed), body: [], next: echo)
        #expect(after.head.headerFields[.setCookie]?.hasPrefix("session=") == true)
    }

    @Test("without a store the signed cookie alone continues the session (stateless, unchanged)")
    func statelessUnchanged() async {
        let middleware = SessionMiddleware(key: key, isSecure: false) { "sid-1" }
        let issued = await middleware.respond(to: request(), body: [], next: echo)
        let cont = await middleware.respond(
            to: request(cookie: signedPair(issued)), body: [], next: echo
        )
        #expect(cont.head.headerFields[.setCookie] == nil)  // no store → HMAC suffices
    }
}
