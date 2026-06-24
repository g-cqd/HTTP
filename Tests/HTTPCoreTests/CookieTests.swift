//
//  CookieTests.swift
//  HTTPCoreTests
//
//  RFC 6265bis — Set-Cookie serialization (with injection-safe validation) and Cookie request parsing.
//

import Testing

@testable import HTTPCore

@Suite("RFC 6265bis — cookies")
struct CookieTests {
    @Test("serializes the attributes in order (RFC 6265bis §4.1.1)")
    func serializesAttributes() {
        let cookie = SetCookie(
            name: "session", value: "abc123", path: "/", maxAge: 3_600, isSecure: true,
            isHTTPOnly: true, sameSite: .lax)
        #expect(
            cookie.headerValue
                == "session=abc123; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax")
    }

    @Test("formats Expires as an IMF-fixdate (RFC 6265bis §4.1.2.1)")
    func formatsExpires() {
        let cookie = SetCookie(name: "id", value: "x", expires: 784_111_777)
        #expect(cookie.headerValue == "id=x; Expires=Sun, 06 Nov 1994 08:49:37 GMT")
    }

    @Test("rejects values that could inject attributes or split the header (CWE-113)")
    func rejectsInjection() {
        #expect(!SetCookie(name: "a", value: "b; Secure").isValid)  // attribute injection
        // Header splitting via CR/LF, and a non-token name.
        #expect(!SetCookie(name: "a", value: "b\r\nSet-Cookie: evil=1").isValid)
        #expect(!SetCookie(name: "bad name", value: "b").isValid)
        #expect(SetCookie(name: "ok", value: "value").isValid)
    }

    @Test("setCookie appends a valid cookie and refuses an invalid one")
    func appendsToFields() {
        var fields = HTTPFields()
        let added = fields.setCookie(SetCookie(name: "a", value: "1"))
        let refused = fields.setCookie(SetCookie(name: "a", value: "x; y"))
        #expect(added)
        #expect(!refused)
        #expect(fields.values(for: .setCookie) == ["a=1"])
    }

    @Test("parses the Cookie header into name→value pairs (RFC 6265bis §4.2.1)")
    func parsesCookieHeader() {
        var fields = HTTPFields()
        _ = fields.append("theme=dark; sessionid=42; empty=", for: .cookie)
        let cookies = Cookies.parse(fields)
        #expect(cookies["theme"] == "dark")
        #expect(cookies["sessionid"] == "42")
        #expect(cookies["empty"] == "")
    }

    @Test("trims surrounding whitespace and ignores malformed pairs")
    func toleratesWhitespaceAndJunk() {
        var fields = HTTPFields()
        _ = fields.append("  a = 1 ;novalue;  b=2  ", for: .cookie)
        let cookies = Cookies.parse(fields)
        #expect(cookies["a"] == "1")
        #expect(cookies["b"] == "2")
        #expect(cookies["novalue"] == nil)
    }
}
