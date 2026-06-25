//
//  HTTPMessageTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for the HTTPRequest / HTTPResponse message value types.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §3 — HTTPRequest")
struct HTTPRequestTests {
    @Test("stores its components")
    func storesComponents() {
        let request = HTTPRequest(
            method: .get,
            scheme: "https",
            authority: "example.com",
            path: "/users"
        )
        #expect(request.method == .get)
        #expect(request.scheme == "https")
        #expect(request.authority == "example.com")
        #expect(request.path == "/users")
        #expect(request.headerFields.isEmpty)
    }

    @Test("effectiveAuthority prefers the :authority control data")
    func effectiveAuthorityPrefersAuthority() {
        var fields = HTTPFields()
        fields.append("from-host.example", for: .host)
        let request = HTTPRequest(
            method: .get,
            authority: "from-authority.example",
            path: "/",
            headerFields: fields
        )
        #expect(request.effectiveAuthority == "from-authority.example")
    }

    @Test("effectiveAuthority falls back to the Host header (RFC 9110 §7.2)")
    func effectiveAuthorityFallsBackToHost() {
        var fields = HTTPFields()
        fields.append("host.example", for: .host)
        let request = HTTPRequest(method: .get, path: "/", headerFields: fields)
        #expect(request.effectiveAuthority == "host.example")
    }

    @Test("effectiveAuthority is nil when neither is present")
    func effectiveAuthorityNilWhenAbsent() {
        let request = HTTPRequest(method: .get, path: "/")
        #expect(request.effectiveAuthority == nil)
    }
}
