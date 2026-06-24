//
//  Cookie.swift
//  HTTPCore
//
//  RFC 6265bis — HTTP state management. `SetCookie` builds a `Set-Cookie` response header from typed
//  attributes (§4.1), validating the name as a token and the value as cookie-octets so an untrusted
//  value cannot inject extra attributes or split the header (CWE-113). `Cookies.parse` reads the
//  `Cookie` request header into name→value pairs (§4.2). Iterative; no Foundation.
//

/// A typed `Set-Cookie` directive (RFC 6265bis §4.1).
public struct SetCookie: Sendable, Equatable {
    /// The `SameSite` attribute (RFC 6265bis §4.1.2.7) — when the cookie accompanies cross-site requests.
    public enum SameSite: String, Sendable, Equatable {
        case strict = "Strict"
        case lax = "Lax"
        case none = "None"
    }

    /// The cookie name (a token).
    public var name: String
    /// The cookie value (cookie-octets).
    public var value: String
    /// `Domain` (§4.1.2.3).
    public var domain: String?
    /// `Path` (§4.1.2.4).
    public var path: String?
    /// `Max-Age` in seconds (§4.1.2.2); `0` or negative expires the cookie immediately.
    public var maxAge: Int?
    /// `Expires` as seconds since the Unix epoch, formatted as an IMF-fixdate (§4.1.2.1).
    public var expires: Int?
    /// `Secure` (§4.1.2.5) — sent only over HTTPS.
    public var isSecure: Bool
    /// `HttpOnly` (§4.1.2.6) — hidden from scripts.
    public var isHTTPOnly: Bool
    /// `SameSite` (§4.1.2.7).
    public var sameSite: SameSite?

    /// Creates a `Set-Cookie` directive (only `name` and `value` are required).
    public init(
        name: String,
        value: String,
        domain: String? = nil,
        path: String? = nil,
        maxAge: Int? = nil,
        expires: Int? = nil,
        isSecure: Bool = false,
        isHTTPOnly: Bool = false,
        sameSite: SameSite? = nil
    ) {
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.maxAge = maxAge
        self.expires = expires
        self.isSecure = isSecure
        self.isHTTPOnly = isHTTPOnly
        self.sameSite = sameSite
    }

    /// The serialized `Set-Cookie` value (RFC 6265bis §4.1.1).
    public var headerValue: String {
        var result = "\(name)=\(value)"
        if let domain { result += "; Domain=\(domain)" }
        if let path { result += "; Path=\(path)" }
        if let maxAge { result += "; Max-Age=\(maxAge)" }
        if let expires { result += "; Expires=\(HTTPDate.imfFixdate(expires))" }
        if isSecure { result += "; Secure" }
        if isHTTPOnly { result += "; HttpOnly" }
        if let sameSite { result += "; SameSite=\(sameSite.rawValue)" }
        return result
    }

    /// Whether the name is a valid token and the value valid cookie-octets (RFC 6265bis §4.1.1) — so
    /// serializing it cannot inject attributes (`;`) or split the header (CR/LF) (CWE-113).
    public var isValid: Bool {
        !name.isEmpty && name.utf8.allSatisfy(Self.isTokenByte)
            && value.utf8.allSatisfy(Self.isCookieOctet)
    }

    /// RFC 9110 token octet (no controls, no separators).
    private static func isTokenByte(_ byte: UInt8) -> Bool {
        switch byte {
            case 0x21, 0x23 ... 0x27, 0x2A, 0x2B, 0x2D, 0x2E, 0x30 ... 0x39, 0x41 ... 0x5A,
                0x5E ... 0x7A,
                0x7C, 0x7E:
                true
            default:
                false
        }
    }

    /// RFC 6265bis cookie-octet: printable ASCII except whitespace, `"`, `,`, `;`, and `\`.
    private static func isCookieOctet(_ byte: UInt8) -> Bool {
        switch byte {
            case 0x21, 0x23 ... 0x2B, 0x2D ... 0x3A, 0x3C ... 0x5B, 0x5D ... 0x7E:
                true
            default:
                false
        }
    }
}

extension HTTPFields {
    /// Appends `cookie` as a `Set-Cookie` header when it is valid; returns whether it was added.
    @discardableResult
    public mutating func setCookie(_ cookie: SetCookie) -> Bool {
        guard cookie.isValid else {
            return false
        }
        return append(cookie.headerValue, for: .setCookie)
    }
}
