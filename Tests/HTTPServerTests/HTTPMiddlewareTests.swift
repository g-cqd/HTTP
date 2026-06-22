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

    private let ok = ClosureResponder { _, _ in
        var fields = HTTPFields()
        _ = fields.append("text/plain", for: .contentType)
        return ServerResponse(
            HTTPResponse(status: .ok, headerFields: fields), body: Array("hi".utf8))
    }

    @Test("a chain runs outermost-first on the way in and unwinds on the way out")
    func chainOrder() async {
        let recorder = Recorder()
        let chain = MiddlewareChain(
            [Tag("a", recorder), Tag("b", recorder)], terminatingAt: ok)
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
            method: .options, scheme: "https", authority: "x", path: "/api", headerFields: fields)
        let response = await ok.wrapped(by: CORSMiddleware()).respond(to: request, body: [])
        #expect(response.head.status == .noContent)
        #expect(response.head.headerFields[.accessControlAllowOrigin] == "*")
        #expect(response.head.headerFields[.accessControlAllowMethods]?.contains("POST") == true)
    }

    @Test("CORSMiddleware echoes the origin and allows credentials when configured")
    func corsCredentials() async {
        var fields = HTTPFields()
        _ = fields.append("https://app.example", for: .origin)
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields)
        let response = await ok.wrapped(by: CORSMiddleware(allowCredentials: true))
            .respond(to: request, body: [])
        #expect(response.head.headerFields[.accessControlAllowOrigin] == "https://app.example")
        #expect(response.head.headerFields[.accessControlAllowCredentials] == "true")
    }

    // MARK: Helpers

    private func get(_ path: String) -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: "x", path: path)
    }
}

/// A thread-safe ordered recorder for chain-order and log assertions.
private final class Recorder: Sendable {
    private let storage = Mutex<[String]>([])
    func add(_ entry: String) { storage.withLock { $0.append(entry) } }
    var entries: [String] { storage.withLock { $0 } }
}

/// A middleware that records its name on the way in and out, around `next`.
private struct Tag: HTTPMiddleware {
    let name: String
    let recorder: Recorder
    init(_ name: String, _ recorder: Recorder) {
        self.name = name
        self.recorder = recorder
    }
    func respond(
        to request: HTTPRequest, body: [UInt8], next: any HTTPResponder
    ) async
        -> ServerResponse
    {
        recorder.add("\(name)→")
        let response = await next.respond(to: request, body: body)
        recorder.add("→\(name)")
        return response
    }
}

/// A middleware that short-circuits the chain with `403 Forbidden`.
private struct Blocker: HTTPMiddleware {
    func respond(
        to request: HTTPRequest, body: [UInt8], next: any HTTPResponder
    ) async
        -> ServerResponse
    {
        ServerResponse(HTTPResponse(status: .forbidden))
    }
}
