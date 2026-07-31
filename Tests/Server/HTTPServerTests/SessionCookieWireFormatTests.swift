//
//  SessionCookieWireFormatTests.swift
//  HTTPServerTests
//
//  The signed session cookie is a wire format: it is handed to a client and presented back, possibly
//  across a deployment that has been upgraded in between. This pins the exact `<id>.<base64url(tag)>`
//  produced for one fixed 32-octet key and one fixed id, so any change to the underlying primitive that
//  would invalidate already-issued cookies fails loudly here. The tag is HMAC-SHA256 (RFC 2104, FIPS
//  180-4) base64url-encoded without padding (RFC 4648 §5) — cross-checked against an independent
//  implementation (`openssl dgst -sha256 -hmac`), so this is a genuine known-answer vector and not a
//  transcription of whatever the code happens to do.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Session cookie — pinned wire format (RFC 2104 tag, RFC 4648 §5 encoding)")
struct SessionCookieWireFormatTests {
    /// Exactly 32 octets — the minimum HMAC-SHA256 key length (NIST SP 800-107r1 §5.3.4).
    private static let key = Array("session-signing-key-0123456789ab".utf8)
    private static let sessionID = "0123456789abcdef0123456789abcdef"
    private static let expectedCookie =
        "session=0123456789abcdef0123456789abcdef.4HXP1DKgEK2_1660XDver_uPnET8im14cmCmRmxs0OU"

    private let echo = ClosureResponder { request, _, _ in
        ServerResponse(HTTPResponse(status: .ok, headerFields: request.headerFields))
    }

    @Test("a fixed key and id produce the exact issued cookie, byte for byte")
    func pinsIssuedCookie() async throws {
        let keys = try #require(SessionSigningKeys(current: Self.key))
        let middleware = SessionMiddleware(keys: keys, isSecure: false) { Self.sessionID }
        let request = HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/")
        let response = await middleware.respond(to: request, body: [], next: echo)
        let setCookie = try #require(response.head.headerFields[.setCookie])
        // Just the `name=value` pair; the attributes (Path/Max-Age/HttpOnly/SameSite) are covered by
        // SessionMiddlewareTests and are not part of the signed value.
        #expect(String(setCookie.prefix { $0 != ";" }) == Self.expectedCookie)
    }

    @Test("the pinned cookie still verifies, and its id is asserted for the handler")
    func pinnedCookieVerifies() async throws {
        let keys = try #require(SessionSigningKeys(current: Self.key))
        let middleware = SessionMiddleware(keys: keys, isSecure: false) { "unused" }
        var fields = HTTPFields()
        _ = fields.append(Self.expectedCookie, for: .cookie)
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        let response = await middleware.respond(to: request, body: [], next: echo)
        #expect(response.head.headerFields[.setCookie] == nil)  // accepted, so no re-issue
        #expect(response.head.headerFields[.xSessionID] == Self.sessionID)
    }
}
