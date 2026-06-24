//
//  SmallMiddlewareTests.swift
//  HTTPServerTests
//
//  The Date, security-headers, and body-limit middlewares.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — Date, security headers, body limit")
struct SmallMiddlewareTests {
    private let ok = ClosureResponder { _, _ in ServerResponse(HTTPResponse(status: .ok)) }

    @Test("DateHeaderMiddleware stamps the injected time as an IMF-fixdate")
    func dateHeader() async {
        let response = await ok.wrapped(by: DateHeaderMiddleware { 784_111_777 })
            .respond(to: request(), body: [])
        #expect(response.head.headerFields[.date] == "Sun, 06 Nov 1994 08:49:37 GMT")
    }

    @Test("SecurityHeadersMiddleware sets the default hardening headers, HSTS off")
    func securityDefaults() async {
        let response = await ok.wrapped(by: SecurityHeadersMiddleware())
            .respond(to: request(), body: [])
        #expect(response.head.headerFields[.xContentTypeOptions] == "nosniff")
        #expect(response.head.headerFields[.xFrameOptions] == "DENY")
        #expect(response.head.headerFields[.referrerPolicy] == "no-referrer")
        #expect(response.head.headerFields[.strictTransportSecurity] == nil)
    }

    @Test("SecurityHeadersMiddleware adds HSTS only when configured")
    func hstsOptIn() async {
        let middleware = SecurityHeadersMiddleware(strictTransportSecurity: "max-age=31536000")
        let response = await ok.wrapped(by: middleware).respond(to: request(), body: [])
        #expect(response.head.headerFields[.strictTransportSecurity] == "max-age=31536000")
    }

    @Test("BodyLimitMiddleware rejects an oversized body with 413")
    func bodyLimitRejects() async {
        let response = await ok.wrapped(by: BodyLimitMiddleware(maxBytes: 4))
            .respond(to: request(), body: Array("too long".utf8))
        #expect(response.head.status == .contentTooLarge)
    }

    @Test("BodyLimitMiddleware passes a body within the limit")
    func bodyLimitPasses() async {
        let response = await ok.wrapped(by: BodyLimitMiddleware(maxBytes: 16))
            .respond(to: request(), body: Array("ok".utf8))
        #expect(response.head.status == .ok)
    }

    private func request() -> HTTPRequest {
        HTTPRequest(method: .post, scheme: "https", authority: "x", path: "/")
    }
}
