//
//  SessionCookieWireFormatTests.swift
//  HTTPServerTests
//
//  The signed session cookie is a wire format: it is handed to a client and presented back, possibly
//  across a deployment that has been upgraded in between. This pins the exact
//  `<id>.<expiry>.<base64url(tag)>` produced for one fixed 32-octet key, one fixed id and one fixed
//  clock, so any change to the underlying primitive that would invalidate already-issued cookies fails
//  loudly here. The tag is HMAC-SHA256 (RFC 2104, FIPS 180-4) base64url-encoded without padding
//  (RFC 4648 §5) — cross-checked against an independent implementation (`openssl dgst -sha256 -hmac`),
//  so this is a genuine known-answer vector and not a transcription of whatever the code happens to do.
//
//  **The format changed once, at audit R5-SEC2, and this file is where that is recorded.** It used to
//  be `<id>.<base64url(HMAC(id))>`. The signed payload carried no expiry, so the tag stayed valid
//  forever and a captured cookie replayed indefinitely (CWE-613); `maxAge` set only the browser's
//  `Max-Age` attribute, which is an instruction to a cooperating user agent rather than a control on an
//  attacker. The payload is now `<id>.<expiry>`, the expiry in whole seconds since the Unix epoch, and
//  the MAC covers both — so the deadline is authenticated and not client-editable.
//
//  Compatibility, stated plainly: a two-part cookie issued before the upgrade is **refused**, and
//  ``SessionExpiryTests`` pins that refusal. Grandfathering it would mean accepting a token with no
//  expiry, which is the entire defect — and a cookie minted before the upgrade is indistinguishable
//  from one an attacker captured before it. The cost is one forced re-issue for every live session at
//  deploy: users are logged out once and get a fresh, bounded cookie on their next request, the same
//  cost a signing-key rotation has always had.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Session cookie — pinned wire format (RFC 2104 tag, RFC 4648 §5 encoding)")
struct SessionCookieWireFormatTests {
    /// Exactly 32 octets — the minimum HMAC-SHA256 key length (NIST SP 800-107r1 §5.3.4).
    private static let key = Array("session-signing-key-0123456789ab".utf8)
    private static let sessionID = "0123456789abcdef0123456789abcdef"

    /// The pinned clock, and the expiry it produces at the default 86 400-second `maxAge`.
    private static let issuedAt = 1_700_000_000
    private static let expiry = 1_700_086_400

    /// The known-answer vector, independently produced.
    ///
    /// Cross-checked with:
    ///
    ///     printf '%s' '0123456789abcdef0123456789abcdef.1700086400' \
    ///       | openssl dgst -sha256 -hmac 'session-signing-key-0123456789ab' -binary \
    ///       | openssl base64 -A | tr '+/' '-_' | tr -d '='
    private static let expectedTag = "_3QQD3GnWAXLiXgIoagvH40n7REJtodtjcKmdgkCxMQ"

    private static let expectedCookie = "session=\(sessionID).\(expiry).\(expectedTag)"

    private let echo = ClosureResponder { request, _, _ in
        ServerResponse(HTTPResponse(status: .ok, headerFields: request.headerFields))
    }

    private func middleware(now: Int) throws -> SessionMiddleware {
        SessionMiddleware(
            keys: try #require(SessionSigningKeys(current: Self.key)),
            isSecure: false,
            generate: { Self.sessionID },
            now: { now }
        )
    }

    @Test("a fixed key, id and clock produce the exact issued cookie, byte for byte")
    func pinsIssuedCookie() async throws {
        let request = HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/")
        let response = try await middleware(now: Self.issuedAt)
            .respond(to: request, body: [], next: echo)
        let setCookie = try #require(response.head.headerFields[.setCookie])
        // Just the `name=value` pair; the attributes (Path/Max-Age/HttpOnly/SameSite) are covered by
        // SessionMiddlewareTests and are not part of the signed value.
        #expect(String(setCookie.prefix { $0 != ";" }) == Self.expectedCookie)
    }

    @Test("the pinned cookie still verifies, and its id is asserted for the handler")
    func pinnedCookieVerifies() async throws {
        var fields = HTTPFields()
        _ = fields.append(Self.expectedCookie, for: .cookie)
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        let response = try await middleware(now: Self.issuedAt + 60)
            .respond(to: request, body: [], next: echo)
        #expect(response.head.headerFields[.setCookie] == nil)  // accepted, so no re-issue
        #expect(response.head.headerFields[.xSessionID] == Self.sessionID)
    }
}
