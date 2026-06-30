//
//  SessionMiddleware.swift
//  HTTPServer
//
//  Tamper-proof session identity via a signed cookie (RFC 6265bis + RFC 9110). The cookie carries a
//  random session id and an HMAC-SHA256 tag over it (`<id>.<base64url(mac)>`); on each request the tag
//  is verified in constant time (``HMACSHA256``), so a client cannot forge or alter the id. A valid session
//  continues untouched; an absent or tampered one is replaced with a fresh signed `Set-Cookie`
//  (`HttpOnly`, `SameSite=Lax`). The verified bare id is asserted onto the request as `X-Session-ID` for
//  the handler — any client-supplied value is stripped, so the handler only ever sees a server-verified
//  id. Stateless by default (the signed cookie is the whole session); pass a ``SessionStore`` to add
//  server-side expiry and revocation (a logout that invalidates a still-unexpired cookie immediately).
//

public import HTTPCore

/// Issues and verifies HMAC-signed session cookies, exposing the verified id as `X-Session-ID`.
public struct SessionMiddleware: HTTPMiddleware {
    private let key: [UInt8]
    private let cookieName: String
    private let maxAge: Int?
    private let isSecure: Bool
    private let generate: @Sendable () -> String
    private let store: (any SessionStore)?

    /// Creates the middleware with the HMAC `key` (keep it secret and stable across restarts).
    ///
    /// `maxAge` bounds the cookie lifetime; `isSecure` marks the cookie `Secure` (HTTPS-only, the safe
    /// default). `generate` defaults to a 128-bit random id. Pass a `store` for server-side expiry and
    /// revocation; omit it (the default) for a fully stateless signed-cookie session.
    public init(
        key: [UInt8],
        cookieName: String = "session",
        maxAge: Int? = 86_400,
        isSecure: Bool = true,
        generate: @escaping @Sendable () -> String = Self.randomID,
        store: (any SessionStore)? = nil
    ) {
        self.key = key
        self.cookieName = cookieName
        self.maxAge = maxAge
        self.isSecure = isSecure
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
        // A cookie must pass the HMAC check and, when a store is configured, also be server-side live
        // (unexpired and unrevoked); otherwise a fresh session is minted.
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

    /// The HMAC-verified `id` when it is also server-side live — or when there is no store (stateless);
    /// `nil` when the store reports it expired or revoked, or when `id` is `nil`.
    private func live(_ id: String?) async -> String? {
        guard let id else {
            return nil
        }
        guard let store else {
            return id  // stateless: HMAC validity is the whole check
        }
        return await store.validate(id) ? id : nil
    }

    /// The verified bare session id from the request's signed cookie, or nil if absent or tampered.
    private func verifiedSession(_ request: HTTPRequest) -> String? {
        guard let raw = Cookies.parse(request.headerFields)[cookieName] else {
            return nil
        }
        let parts = raw.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
            let mac = Base64.decode(parts[1].utf8, alphabet: .urlSafe, padded: false)
        else {
            return nil
        }
        let id = String(parts[0])
        let expected = HMACSHA256.authenticationCode(key: key, message: Array(id.utf8))
        let valid = HMACSHA256.constantTimeEquals(mac, expected)
        return valid ? id : nil
    }

    /// Signs `id` as `<id>.<base64url(HMAC-SHA256(id))>`.
    private func sign(_ id: String) -> String {
        let mac = HMACSHA256.authenticationCode(key: key, message: Array(id.utf8))
        return id + "." + Base64.encode(mac, alphabet: .urlSafe, padded: false)
    }

    /// A 128-bit random hex session id (`SystemRandomNumberGenerator`).
    public static func randomID() -> String {
        var rng = SystemRandomNumberGenerator()
        let high = UInt64.random(in: .min ... .max, using: &rng)
        let low = UInt64.random(in: .min ... .max, using: &rng)
        return String(high, radix: 16) + String(low, radix: 16)
    }
}
