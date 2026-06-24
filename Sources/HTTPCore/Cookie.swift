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

    /// The serialized `Set-Cookie` value (RFC 6265bis §4.1.1), or `nil` when the cookie is invalid.
    ///
    /// Returning `nil` for an invalid cookie is fail-closed by construction: a name / value / attribute
    /// carrying an injection octet can never be serialized into a header (CWE-113), even by a caller
    /// that uses this directly rather than going through ``HTTPFields/setCookie(_:)``.
    public var headerValue: String? {
        guard isValid else {
            return nil
        }
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

    /// Whether the name, value, and every attribute are injection-safe (RFC 6265bis §4.1.1) — so
    /// serializing the cookie cannot inject an attribute (`;`) or split the header (CR/LF) (CWE-113),
    /// and the `__Host-` / `__Secure-` name prefixes carry their required attributes (§4.1.3).
    public var isValid: Bool {
        !name.isEmpty && name.utf8.allSatisfy(Self.isTokenByte)
            && value.utf8.allSatisfy(Self.isCookieOctet)
            && (domain?.utf8.allSatisfy(Self.isDomainByte) ?? true)
            && (path?.utf8.allSatisfy(Self.isPathByte) ?? true)
            && satisfiesNamePrefix
    }

    /// The `__Host-` / `__Secure-` cookie-name prefix invariants (RFC 6265bis §4.1.3).
    ///
    /// `__Secure-` requires `Secure`; `__Host-` additionally forbids `Domain` and pins `Path` to `/`,
    /// so a prefixed cookie cannot be set by a weaker (non-HTTPS, cross-host, or scoped) writer.
    private var satisfiesNamePrefix: Bool {
        if name.hasPrefix("__Host-") {
            return isSecure && domain == nil && path == "/"
        }
        if name.hasPrefix("__Secure-") {
            return isSecure
        }
        return true
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

    /// RFC 6265bis path-av octet: any CHAR except CTLs and `;`, so a `Path` cannot inject an attribute
    /// or split the header.
    private static func isPathByte(_ byte: UInt8) -> Bool {
        byte >= 0x20 && byte != 0x7F && byte != 0x3B
    }

    /// A conservative `Domain` octet — letters, digits, `-`, `.` (host characters) — rejecting `;`,
    /// CR/LF, whitespace, and other separators so a `Domain` cannot inject an attribute or split the
    /// header.
    private static func isDomainByte(_ byte: UInt8) -> Bool {
        switch byte {
            case 0x30 ... 0x39, 0x41 ... 0x5A, 0x61 ... 0x7A, 0x2D, 0x2E:
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
        guard let headerValue = cookie.headerValue else {
            return false
        }
        return append(headerValue, for: .setCookie)
    }
}
