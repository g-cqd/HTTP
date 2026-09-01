//
//  SessionMiddleware.swift
//  HTTPServer
//
//  Tamper-proof session identity via a signed cookie (RFC 6265bis + RFC 9110). The cookie carries a
//  random session id, an absolute expiry, and an HMAC-SHA256 tag over the pair
//  (`<id>.<expiry>.<base64url(mac)>`); on each request the tag is verified in constant time against
//  every key in ``SessionSigningKeys``, so a client cannot forge or alter either field, and a signing
//  key can be rotated without logging everyone out. A valid, unexpired session continues untouched; an
//  absent, tampered, or expired one is replaced with a fresh signed `Set-Cookie` (`HttpOnly`,
//  `SameSite=Lax`). The verified bare id is asserted onto the request as `X-Session-ID` for the handler
//  — any client-supplied value is stripped, so the handler only ever sees a server-verified id.
//  Stateless by default (the signed cookie is the whole session); pass a ``SessionStore`` to add
//  revocation and an idle timeout on top (a logout that invalidates a still-unexpired cookie).
//
//  **Why the expiry is inside the signature** (audit R5-SEC2, CWE-613 — insufficient session
//  expiration). `maxAge` used to set only the browser's `Max-Age` attribute (RFC 6265bis §4.1.2.2), and
//  the signed token carried no deadline at all: its HMAC stayed valid forever, so a captured cookie
//  replayed indefinitely. `Max-Age` is an instruction to a cooperating user agent, and an attacker
//  holding a stolen cookie is not running one — it is a usability hint, never a security control.
//  OWASP ASVS 5.0 §3.3 puts the absolute lifetime on the *server*, which for a stateless session means
//  inside the authenticated payload. The MAC covers `<id>.<expiry>` rather than `<id>` alone precisely
//  so the deadline is not client-editable, and verification checks the MAC *before* parsing the expiry:
//  until the tag verifies, the expiry is attacker-controlled bytes and must not be believed.
//
//  This also gives the *stateful* path a bound it never had. ``InMemorySessionStore`` enforces a
//  sliding TTL that each `validate` refreshes, so a session replayed once a minute stayed live in it
//  forever; the store bounds idleness, not lifetime. The token's expiry is checked before the store is
//  ever consulted, so both configurations now have an absolute cap and the store keeps doing the two
//  things only it can — immediate revocation, and an idle timeout.
//
//  Wire format compatibility: the pre-SEC2 two-part `<id>.<mac>` cookie is **refused**, not
//  grandfathered. It carries no expiry, so accepting it would preserve exactly the unbounded replay
//  this removes — a cookie minted before the upgrade is indistinguishable from one an attacker
//  captured before it. The cost is that every live session is invalidated once, at deploy: users are
//  logged out and immediately get a fresh, bounded cookie on their next request. Rotating a signing key
//  has always had that cost; this pays it once, deliberately, and `SessionCookieWireFormatTests` pins
//  the new format so a further change fails loudly.
//

internal import Foundation
public import HTTPCore

/// Issues and verifies HMAC-signed, self-expiring session cookies, exposing the id as `X-Session-ID`.
public struct SessionMiddleware: HTTPMiddleware {
    /// The token lifetime applied when `maxAge` is `nil` — one day, in seconds.
    ///
    /// A `nil` `maxAge` means "send no `Max-Age` attribute", i.e. a browser-session cookie. That is a
    /// statement about the *browser*, and the browser is not the security boundary (R5-SEC2), so the
    /// token still carries a server-enforced deadline; this is it.
    public static let defaultTokenLifetimeSeconds = 86_400

    /// The shipped clock the `now` seam defaults to: seconds since the Unix epoch, from the system
    /// wall clock.
    ///
    /// Wall clock rather than monotonic on purpose — the expiry is written into a token that outlives
    /// the process and may be verified by a different one, so it has to be an absolute instant both
    /// agree on. A monotonic reading is meaningless across a restart, which is precisely the case a
    /// stateless session exists to survive.
    public static let wallClockSeconds: @Sendable () -> Int = { Int(Date().timeIntervalSince1970) }

    private let keys: SessionSigningKeys
    private let cookieName: String
    private let maxAge: Int?
    private let isSecure: Bool
    private let now: @Sendable () -> Int
    private let generate: @Sendable () -> String
    private let store: (any SessionStore)?

    /// Creates the middleware with the signing `keys` (keep them secret and stable across restarts).
    ///
    /// `maxAge` bounds the session in seconds — both the cookie's `Max-Age` attribute *and* the expiry
    /// signed into the token; `nil` sends no attribute (a browser-session cookie) while still bounding
    /// the token by ``defaultTokenLifetimeSeconds``. `isSecure` marks the cookie `Secure` (HTTPS-only,
    /// the safe default). `now` returns seconds since the Unix epoch and is injectable for tests.
    /// `generate` defaults to a 128-bit random id, and must not produce a `.` (the token's field
    /// separator); ``randomID()`` is hex, so it cannot. Pass a `store` for revocation and an idle
    /// timeout on top of the token's absolute expiry; omit it for a fully stateless session.
    public init(
        keys: SessionSigningKeys,
        cookieName: String = "session",
        maxAge: Int? = 86_400,
        isSecure: Bool = true,
        // `now` sits after `generate` deliberately: a bare trailing closure forward-scans to the first
        // unfilled closure parameter, so putting the clock first would silently re-bind every existing
        // `SessionMiddleware(keys:) { id }` call site to it.
        generate: @escaping @Sendable () -> String = Self.randomID,
        now: @escaping @Sendable () -> Int = Self.wallClockSeconds,
        store: (any SessionStore)? = nil
    ) {
        self.keys = keys
        self.cookieName = cookieName
        self.maxAge = maxAge
        self.isSecure = isSecure
        self.now = now
        self.generate = generate
        self.store = store
    }

    /// Verifies (or mints) the session, asserts the id on the request, and re-issues the cookie if new.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        // A cookie must pass the HMAC check AND still be inside the expiry signed into it, and when a
        // store is configured also be server-side live (unrevoked, not idle out); else a fresh
        // session is minted. The token's absolute expiry is checked first, so it bounds both the
        // stateless and the store-backed configuration (R5-SEC2).
        let verified = await live(verifiedSession(request))
        let id = verified ?? generate()
        var request = request
        _ = request.headerFields.setValue(id, for: .xSessionID)  // strip any spoof; assert verified
        if verified == nil {
            // Register the freshly minted session as live before the handler runs.
            await store?.register(id)
        }
        var response = await next.respond(to: request, body: body, context: context)
        if verified == nil {
            let cookie = SetCookie(
                name: cookieName,
                value: sign(id),
                path: "/",
                maxAge: maxAge,
                isSecure: isSecure,
                isHTTPOnly: true,
                sameSite: .lax
            )
            _ = response.head.headerFields.setCookie(cookie)
        }
        return response
    }

    /// The verified, unexpired `id` when it is also server-side live — or when there is no store
    /// (stateless); `nil` when the store reports it idle-timed-out or revoked, or when `id` is `nil`.
    private func live(_ id: String?) async -> String? {
        guard let id else {
            return nil
        }
        guard let store else {
            return id  // stateless: the tag and the token's own expiry are the whole check
        }
        return await store.validate(id) ? id : nil
    }

    /// The verified bare session id from the request's signed cookie — nil if absent, tampered, or
    /// past the expiry the token itself carries (R5-SEC2).
    private func verifiedSession(_ request: HTTPRequest) -> String? {
        guard let raw = Cookies.parse(request.headerFields)[cookieName] else {
            return nil
        }
        // `<id>.<expiry>.<mac>`. Exactly three parts: a pre-SEC2 two-part cookie carries no expiry
        // and is refused here rather than grandfathered — see the file comment.
        let parts = raw.split(separator: ".", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3,
            let mac = Base64.decode(parts[2].utf8, alphabet: .urlSafe, padded: false)
        else {
            return nil
        }
        // Authenticate FIRST, over the payload exactly as it arrived on the wire. Everything before
        // this line is attacker-controlled, including the deadline, so nothing may be believed until
        // the tag verifies (CWE-565, reliance on a cookie without integrity checking).
        let payload = raw.dropLast(parts[2].count + 1)
        guard keys.isValid(tag: mac, for: Array(payload.utf8)) else {
            return nil
        }
        guard let expiry = Int(parts[1]), now() < expiry else {
            return nil  // unparsable or elapsed — never "unbounded"
        }
        return String(parts[0])
    }

    /// Signs `id` as `<id>.<expiry>.<base64url(HMAC-SHA256(<id>.<expiry>))>` under the current key.
    ///
    /// The tag covers the expiry as well as the id, so a client cannot push its own deadline out.
    private func sign(_ id: String) -> String {
        let lifetime = maxAge ?? Self.defaultTokenLifetimeSeconds
        // Saturating: an absurd `maxAge` must not trap the way an unguarded sum would (R5-VAL taught
        // this lesson two commits ago). `Int.max` seconds is "no practical expiry", which is the
        // honest reading of what such a configuration asked for.
        let sum = now().addingReportingOverflow(lifetime)
        let payload = "\(id).\(sum.overflow ? Int.max : sum.partialValue)"
        let mac = keys.tag(for: Array(payload.utf8))
        return payload + "." + Base64.encode(mac, alphabet: .urlSafe, padded: false)
    }

    /// A 128-bit random session id as exactly 32 lowercase hex digits (``RandomToken/hex128()``).
    public static func randomID() -> String {
        RandomToken.hex128()
    }
}
