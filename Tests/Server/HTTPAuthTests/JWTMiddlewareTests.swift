//
//  JWTMiddlewareTests.swift
//  HTTPAuthTests
//
//  RFC 6750 — a valid Bearer token is accepted and its `sub` asserted on `.xAuthSubject`; a missing or
//  invalid token is a `401` carrying the `Bearer` challenge.
//

import HTTPAuth
import HTTPCore
import HTTPServer
import Testing

@Suite("HTTPAuth — JWT Bearer middleware (RFC 6750)")
struct JWTMiddlewareTests {
    private let secret: [UInt8] = Array("0123456789abcdef0123456789abcdef".utf8)
    private let header = #"{"alg":"HS256","typ":"JWT"}"#

    @Test("a valid Bearer token is accepted and exposes sub on .xAuthSubject")
    func accepts() async {
        let token = TokenFactory.hs256(
            header: header, payload: #"{"sub":"alice","exp":2000}"#, secret: secret
        )
        let middleware = JWTMiddleware(key: .hs256(secret)) { 1_000 }
        let response = await AuthHarness.run(middleware, authorization: "Bearer " + token)
        #expect(response.head.status.code == 200)
        #expect(response.head.headerFields[.xAuthSubject] == "alice")
    }

    @Test("an expired token is 401 with the Bearer challenge")
    func rejectsExpired() async {
        let token = TokenFactory.hs256(header: header, payload: #"{"exp":500}"#, secret: secret)
        let middleware = JWTMiddleware(key: .hs256(secret)) { 1_000 }
        let response = await AuthHarness.run(middleware, authorization: "Bearer " + token)
        #expect(response.head.status.code == 401)
        #expect(response.head.headerFields[.wwwAuthenticate]?.contains("Bearer") == true)
        #expect(response.head.headerFields[.xAuthSubject] == nil)
    }

    @Test("a missing token is 401")
    func missing() async {
        let middleware = JWTMiddleware(key: .hs256(secret)) { 1_000 }
        let response = await AuthHarness.run(middleware, authorization: nil)
        #expect(response.head.status.code == 401)
    }
}
