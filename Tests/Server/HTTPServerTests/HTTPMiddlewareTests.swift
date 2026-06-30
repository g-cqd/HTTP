//
//  HTTPMiddlewareTests.swift
//  HTTPServerTests
//
//  The middleware abstraction: chain ordering (outermost-first), short-circuiting, and the built-in
//  Server-header, access-log, and CORS middlewares.
//

import HTTPCore
import Synchronization
import Testing

@testable import HTTPServer

@Suite("Middleware — composition + built-ins")
struct HTTPMiddlewareTests {
    private let ok = ClosureResponder { _, _, _ in
        var fields = HTTPFields()
        _ = fields.append("text/plain", for: .contentType)
        return ServerResponse(
            HTTPResponse(status: .ok, headerFields: fields), body: Array("hi".utf8)
        )
    }

    @Test("a chain runs outermost-first on the way in and unwinds on the way out")
    func chainOrder() async {
        let recorder = Recorder()
        let chain = MiddlewareChain([Tag("a", recorder), Tag("b", recorder)], terminatingAt: ok)
        _ = await chain.respond(to: get("/"), body: [])
        #expect(recorder.entries == ["a→", "b→", "→b", "→a"])
    }

    @Test("a middleware can short-circuit without calling next")
    func shortCircuit() async {
        let responder = ok.wrapped(by: Blocker())
        #expect(await responder.respond(to: get("/"), body: []).head.status == .forbidden)
    }

    @Test("ServerHeaderMiddleware stamps Server when the responder did not")
    func serverHeader() async {
        let responder = ok.wrapped(by: ServerHeaderMiddleware("test-server"))
        let response = await responder.respond(to: get("/"), body: [])
        #expect(response.head.headerFields[.server] == "test-server")
    }

    @Test("AccessLogMiddleware logs the method, path, and status")
    func accessLog() async {
        let sink = Recorder()
        let responder = ok.wrapped(by: AccessLogMiddleware { sink.add($0) })
        _ = await responder.respond(to: get("/health"), body: [])
        #expect(sink.entries == ["GET /health -> 200"])
    }

    @Test("CORSMiddleware answers a preflight with 204 and the allow headers")
    func corsPreflight() async {
        var fields = HTTPFields()
        _ = fields.append("https://app.example", for: .origin)
        _ = fields.append("POST", for: .accessControlRequestMethod)
        let request = HTTPRequest(
            method: .options, scheme: "https", authority: "x", path: "/api", headerFields: fields
        )
        let response = await ok.wrapped(by: CORSMiddleware()).respond(to: request, body: [])
        #expect(response.head.status == .noContent)
        #expect(response.head.headerFields[.accessControlAllowOrigin] == "*")
        #expect(response.head.headerFields[.accessControlAllowMethods]?.contains("POST") == true)
    }

    @Test("CORSMiddleware reflects an allow-listed origin with credentials + Vary: Origin")
    func corsCredentials() async {
        var fields = HTTPFields()
        _ = fields.append("https://app.example", for: .origin)
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        let cors = CORSMiddleware(
            allowedOrigin: .allowList(["https://app.example"]), allowCredentials: true
        )
        let response = await ok.wrapped(by: cors).respond(to: request, body: [])
        #expect(response.head.headerFields[.accessControlAllowOrigin] == "https://app.example")
        #expect(response.head.headerFields[.accessControlAllowCredentials] == "true")
        #expect(response.head.headerFields[.vary]?.lowercased().contains("origin") == true)
    }

    @Test("CORSMiddleware never pairs a wildcard origin with credentials (CWE-942 fail-safe)")
    func corsWildcardNeverCredentialed() async {
        var fields = HTTPFields()
        _ = fields.append("https://evil.example", for: .origin)
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        // `.any` + credentials is a footgun (reflect-any-origin-with-credentials); the middleware
        // fails safe to a credential-free wildcard.
        let cors = CORSMiddleware(allowedOrigin: .any, allowCredentials: true)
        let response = await ok.wrapped(by: cors).respond(to: request, body: [])
        #expect(response.head.headerFields[.accessControlAllowOrigin] == "*")
        #expect(response.head.headerFields[.accessControlAllowCredentials] == nil)
    }

    @Test("CORSMiddleware denies an origin not on the allow-list (no ACAO, Vary: Origin)")
    func corsAllowListDenies() async {
        var fields = HTTPFields()
        _ = fields.append("https://evil.example", for: .origin)
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        let cors = CORSMiddleware(allowedOrigin: .allowList(["https://app.example"]))
        let response = await ok.wrapped(by: cors).respond(to: request, body: [])
        #expect(response.head.headerFields[.accessControlAllowOrigin] == nil)
        #expect(response.head.headerFields[.vary]?.lowercased().contains("origin") == true)
    }

    // MARK: Helpers

    private func get(_ path: String) -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: "x", path: path)
    }
}
