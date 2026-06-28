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
//  id. Stateless: the signed cookie is the whole session, so it needs no server-side store.
//

internal import Foundation
public import HTTPCore

/// Issues and verifies HMAC-signed session cookies, exposing the verified id as `X-Session-ID`.
public struct SessionMiddleware: HTTPMiddleware {
    private let key: [UInt8]
    private let cookieName: String
    private let maxAge: Int?
    private let isSecure: Bool
    private let generate: @Sendable () -> String

    /// Creates the middleware with the HMAC `key` (keep it secret and stable across restarts).
    ///
    /// `maxAge` bounds the cookie lifetime; `isSecure` marks the cookie `Secure` (HTTPS-only, the safe
    /// default). `generate` defaults to a 128-bit random id.
    public init(
        key: [UInt8],
        cookieName: String = "session",
        maxAge: Int? = 86_400,
        isSecure: Bool = true,
        generate: @escaping @Sendable () -> String = Self.randomID
    ) {
        self.key = key
        self.cookieName = cookieName
        self.maxAge = maxAge
        self.isSecure = isSecure
        self.generate = generate
    }

    /// Verifies (or mints) the session, asserts the id on the request, and re-issues the cookie if new.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        let verified = verifiedSession(request)
        let id = verified ?? generate()
        var request = request
        _ = request.headerFields.setValue(id, for: .xSessionID)  // strip any spoof; assert verified
        var response = await next.respond(to: request, body: body)
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

    /// The verified bare session id from the request's signed cookie, or nil if absent or tampered.
    private func verifiedSession(_ request: HTTPRequest) -> String? {
        guard let raw = Cookies.parse(request.headerFields)[cookieName] else {
            return nil
        }
        let parts = raw.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let mac = Self.base64urlDecode(String(parts[1])) else {
            return nil
        }
        let id = String(parts[0])
        let expected = HMACSHA256.authenticationCode(key: key, message: Array(id.utf8))
        let valid = HMACSHA256.constantTimeEquals(Array(mac), expected)
        return valid ? id : nil
    }

    /// Signs `id` as `<id>.<base64url(HMAC-SHA256(id))>`.
    private func sign(_ id: String) -> String {
        let mac = HMACSHA256.authenticationCode(key: key, message: Array(id.utf8))
        return id + "." + Self.base64urlEncode(Data(mac))
    }

    /// A 128-bit random hex session id (`SystemRandomNumberGenerator`).
    public static func randomID() -> String {
        var rng = SystemRandomNumberGenerator()
        let high = UInt64.random(in: .min ... .max, using: &rng)
        let low = UInt64.random(in: .min ... .max, using: &rng)
        return String(high, radix: 16) + String(low, radix: 16)
    }

    /// Base64url without padding (cookie-safe; RFC 4648 §5).
    private static func base64urlEncode(_ data: Data) -> String {
        var encoded = data.base64EncodedString()
        encoded = encoded.replacingOccurrences(of: "+", with: "-")
        encoded = encoded.replacingOccurrences(of: "/", with: "_")
        while encoded.hasSuffix("=") {
            encoded.removeLast()
        }
        return encoded
    }

    /// Decodes a base64url (unpadded) string, or nil if malformed.
    ///
    /// Strict (RFC 4648 §5): rejects any byte outside the URL alphabet — standard `+`/`/`, embedded `=`
    /// padding, and whitespace — so a tag cannot be silently rewritten into an equivalent encoding before
    /// the constant-time compare (audit F8; matches `HTTPAuth/Base64URL`).
    private static func base64urlDecode(_ string: String) -> Data? {
        for scalar in string.unicodeScalars {
            switch scalar {
                case "A" ... "Z", "a" ... "z", "0" ... "9", "-", "_":
                    continue
                default:
                    return nil
            }
        }
        var standard = string.replacingOccurrences(of: "-", with: "+")
        standard = standard.replacingOccurrences(of: "_", with: "/")
        while standard.count % 4 != 0 {
            standard += "="
        }
        return Data(base64Encoded: standard)
    }
}
