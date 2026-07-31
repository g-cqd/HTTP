//
//  JWTMiddlewareTests.swift
//  HTTPAuthTests
//
//  RFC 6750 — a valid Bearer token is accepted and its `sub` asserted on `.xAuthSubject`; a missing or
//  invalid token is a `401` carrying the `Bearer` challenge.
//

import Crypto
import HTTPAuth
import HTTPCore
import HTTPServer
import Testing

@Suite("HTTPAuth — JWT Bearer middleware (RFC 6750)")
struct JWTMiddlewareTests {
    private let secret: [UInt8] = Array("0123456789abcdef0123456789abcdef".utf8)
    private let header = #"{"alg":"HS256","typ":"JWT"}"#

    /// The HS256 verification key for ``secret``, built from the shared 32-octet test secret.
    private var hsKey: JWT.Key { .hs256(SymmetricKey(data: secret)) }

    @Test("a valid Bearer token is accepted and exposes sub on .xAuthSubject")
    func accepts() async {
        let token = TokenFactory.hs256(
            header: header, payload: #"{"sub":"alice","exp":2000}"#, secret: secret
        )
        let middleware = JWTMiddleware(key: hsKey) { 1_000 }
        let response = await AuthHarness.run(middleware, authorization: "Bearer " + token)
        #expect(response.head.status.code == 200)
        #expect(response.head.headerFields[.xAuthSubject] == "alice")
    }

    @Test("an expired token is 401 with the Bearer challenge")
    func rejectsExpired() async {
        let token = TokenFactory.hs256(header: header, payload: #"{"exp":500}"#, secret: secret)
        let middleware = JWTMiddleware(key: hsKey) { 1_000 }
        let response = await AuthHarness.run(middleware, authorization: "Bearer " + token)
        #expect(response.head.status.code == 401)
        #expect(response.head.headerFields[.wwwAuthenticate]?.contains("Bearer") == true)
        #expect(response.head.headerFields[.xAuthSubject] == nil)
    }

    @Test("a missing token is 401")
    func missing() async {
        let middleware = JWTMiddleware(key: hsKey) { 1_000 }
        let response = await AuthHarness.run(middleware, authorization: nil)
        #expect(response.head.status.code == 401)
    }

    // MARK: A verified token that names no principal (audit CR-F13, RFC 7519 §4.1.2)

    @Test("a valid token with no sub is 401 by default and forwards no spoofed subject")
    func rejectsSubjectlessTokenByDefault() async {
        let token = TokenFactory.hs256(
            header: header, payload: #"{"exp":2000}"#, secret: secret
        )
        let middleware = JWTMiddleware(key: hsKey) { 1_000 }
        let response = await AuthHarness.run(
            middleware, authorization: "Bearer " + token, spoofing: "attacker"
        )
        #expect(response.head.status.code == 401)
        // The handler never ran, so nothing echoed the spoofed value back.
        #expect(response.head.headerFields[.xAuthSubject] == nil)
    }

    @Test(
        "with requireSubject: false a subjectless token removes .xAuthSubject rather than forwarding"
    )
    func optedOutTokenRemovesTheSpoofedSubject() async {
        let token = TokenFactory.hs256(
            header: header, payload: #"{"exp":2000}"#, secret: secret
        )
        let middleware = JWTMiddleware(key: hsKey, requireSubject: false) { 1_000 }
        let response = await AuthHarness.run(
            middleware, authorization: "Bearer " + token, spoofing: "attacker"
        )
        // Authenticated, just not identified.
        #expect(response.head.status.code == 200)
        #expect(response.head.headerFields[.xAuthSubject] == nil)  // and NOT "attacker"
    }

    @Test("a verified subject replaces a client-supplied one")
    func verifiedSubjectReplacesSpoof() async {
        let token = TokenFactory.hs256(
            header: header, payload: #"{"sub":"alice","exp":2000}"#, secret: secret
        )
        let middleware = JWTMiddleware(key: hsKey) { 1_000 }
        let response = await AuthHarness.run(
            middleware, authorization: "Bearer " + token, spoofing: "attacker"
        )
        #expect(response.head.status.code == 200)
        #expect(response.head.headerFields[.xAuthSubject] == "alice")
    }
}
