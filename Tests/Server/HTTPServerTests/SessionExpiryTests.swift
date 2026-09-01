//
//  SessionExpiryTests.swift
//  HTTPServerTests
//
//  Audit R5-SEC2 — a stateless session cookie must expire server-side (CWE-613, insufficient session
//  expiration).
//
//  `maxAge` set only the browser's `Max-Age` attribute (RFC 6265bis §4.1.2.2). The signed token itself
//  carried no expiry, so its HMAC stayed valid forever and a captured cookie replayed indefinitely: the
//  `Max-Age` is a hint to a cooperating user agent, and an attacker holding a stolen cookie is not
//  running one. OWASP ASVS 5.0 §3.3 requires the *server* to bound a session's absolute lifetime.
//
//  The token now carries an authenticated expiry — `<id>.<expiry>.<mac>`, with the MAC taken over
//  `<id>.<expiry>` so the deadline cannot be edited — and verification refuses a token past it. The
//  order matters and is asserted below: the MAC is checked *before* the expiry is parsed, because until
//  the MAC verifies, the expiry is attacker-controlled bytes.
//
//  The stateful path gets the same bound for free, which is the point of putting the expiry in the
//  token rather than in the store. `InMemorySessionStore` enforces a *sliding* TTL that every
//  `validate` refreshes, so a session replayed once a minute stayed live forever — no absolute cap.
//  The token expiry is checked before the store is ever consulted, so it now bounds both paths.
//

import HTTPConcurrency
import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Sessions — the signed token expires server-side (CWE-613, R5-SEC2)")
struct SessionExpiryTests {
    /// Exactly 32 octets — the minimum HMAC-SHA256 key length (NIST SP 800-107r1 §5.3.4).
    private static let key = Array("session-signing-key-0123456789ab".utf8)
    private static let issuedAt = 1_700_000_000

    private let echo = ClosureResponder { request, _, _ in
        ServerResponse(HTTPResponse(status: .ok, headerFields: request.headerFields))
    }

    private func keys() throws -> SessionSigningKeys {
        try #require(SessionSigningKeys(current: Self.key))
    }

    /// The `name=value` pair of the `Set-Cookie` a middleware pinned at `issuedAt` mints.
    private func issueCookie(
        maxAge: Int? = 86_400,
        store: (any SessionStore)? = nil
    ) async throws -> String {
        let middleware = SessionMiddleware(
            keys: try keys(),
            maxAge: maxAge,
            isSecure: false,
            generate: { "0123456789abcdef0123456789abcdef" },
            now: { Self.issuedAt },
            store: store
        )
        let response = await middleware.respond(to: Self.request(), body: [], next: echo)
        let setCookie = try #require(response.head.headerFields[.setCookie])
        return String(setCookie.prefix { $0 != ";" })
    }

    /// Replays `cookie` against a middleware whose clock reads `at`, returning what the handler saw.
    private func replay(
        _ cookie: String,
        at instant: Int,
        store: (any SessionStore)? = nil
    ) async throws -> (sessionID: String?, reissued: Bool) {
        let middleware = SessionMiddleware(
            keys: try keys(),
            isSecure: false,
            generate: { "freshly-minted-replacement-00000" },
            now: { instant },
            store: store
        )
        let response = await middleware.respond(
            to: Self.request(cookie: cookie), body: [], next: echo
        )
        return (
            response.head.headerFields[.xSessionID],
            response.head.headerFields[.setCookie] != nil
        )
    }

    @Test("a cookie replayed inside its lifetime is still accepted")
    func liveTokenIsAccepted() async throws {
        let cookie = try await issueCookie()
        let seen = try await replay(cookie, at: Self.issuedAt + 86_399)
        #expect(seen.sessionID == "0123456789abcdef0123456789abcdef")
        #expect(!seen.reissued)
    }

    @Test(
        "an expired token is refused however the client replays it",
        arguments: [86_400, 86_401, 90_000, 10 * 86_400, 365 * 86_400]
    )
    func expiredTokenIsRefused(_ elapsed: Int) async throws {
        let cookie = try await issueCookie()
        let seen = try await replay(cookie, at: Self.issuedAt + elapsed)
        // The captured cookie buys nothing: the handler sees a brand new id, and a new one is issued.
        #expect(seen.sessionID != "0123456789abcdef0123456789abcdef")
        #expect(seen.reissued)
    }

    @Test("the expiry is authenticated — extending it by hand invalidates the token")
    func expiryIsCoveredByTheMAC() async throws {
        let cookie = try await issueCookie()
        let value = String(cookie.drop { $0 != "=" }.dropFirst())
        let parts = value.split(separator: ".", maxSplits: 2, omittingEmptySubsequences: false)
        #expect(parts.count == 3)
        // Same id, same tag, a deadline pushed a decade out: the MAC covers `<id>.<expiry>`, so this
        // is a forgery rather than a renewal (CWE-565, reliance on a cookie without integrity check).
        let forged = "session=\(parts[0]).\(Self.issuedAt + 315_360_000).\(parts[2])"
        let seen = try await replay(forged, at: Self.issuedAt + 86_401)
        #expect(seen.sessionID != String(parts[0]))
        #expect(seen.reissued)
    }

    @Test("a token whose expiry is not a number is refused, not treated as unbounded")
    func unparsableExpiryIsRefused() async throws {
        let seen = try await replay(
            "session=0123456789abcdef0123456789abcdef.forever.AAAA", at: Self.issuedAt
        )
        #expect(seen.reissued)
    }

    @Test("a legacy two-part cookie carries no expiry and is refused (the compatibility story)")
    func legacyTwoPartCookieIsRefused() async throws {
        // The pre-SEC2 wire format, signed with the same live key. It is refused *because* it has no
        // expiry: honoring it would preserve exactly the unbounded replay this change removes.
        let legacy =
            "session=0123456789abcdef0123456789abcdef"
            + ".4HXP1DKgEK2_1660XDver_uPnET8im14cmCmRmxs0OU"
        let seen = try await replay(legacy, at: Self.issuedAt)
        #expect(seen.sessionID != "0123456789abcdef0123456789abcdef")
        #expect(seen.reissued)
    }

    @Test("a nil maxAge still bounds the token — the browser hint is not the control")
    func nilMaxAgeStillExpires() async throws {
        let cookie = try await issueCookie(maxAge: nil)
        #expect(!cookie.contains("Max-Age"))
        let lifetime = SessionMiddleware.defaultTokenLifetimeSeconds
        #expect(try await replay(cookie, at: Self.issuedAt + lifetime - 1).sessionID != nil)
        #expect(try await replay(cookie, at: Self.issuedAt + lifetime).reissued)
    }

    @Test("the stateful path inherits the absolute bound its sliding TTL never had")
    func storeBackedSessionIsAlsoBounded() async throws {
        // The store's TTL slides on every validate, so a session replayed once a minute stays live in
        // it forever. Drive exactly that: keep the store's view fresh right up to the token's expiry,
        // then step past it. The store still says live; the token says no, and the token wins.
        let clock = TestMonotonicClock()
        let store = InMemorySessionStore(ttl: .seconds(600), now: clock.now)
        let cookie = try await issueCookie(store: store)
        var instant = Self.issuedAt
        while instant < Self.issuedAt + 86_400 - 300 {
            instant += 300
            clock.advance(by: .seconds(300))
            #expect(try await replay(cookie, at: instant, store: store).sessionID != nil)
        }
        clock.advance(by: .seconds(300))
        let past = try await replay(cookie, at: Self.issuedAt + 86_400, store: store)
        #expect(past.reissued)
    }

    private static func request(cookie: String? = nil) -> HTTPRequest {
        var fields = HTTPFields()
        if let cookie { _ = fields.append(cookie, for: .cookie) }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }
}
