//
//  ConditionalRequestMiddlewareTests.swift
//  HTTPServerTests
//
//  Conditional requests (RFC 9110 §13): ETag generation, the If-None-Match → 304 collapse, and weak
//  comparison.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — conditional requests (ETag / 304)")
struct ConditionalRequestMiddlewareTests {

    private func body(_ text: String, status: HTTPStatus = .ok) -> any HTTPResponder {
        ClosureResponder { _, _ in
            ServerResponse(HTTPResponse(status: status), body: Array(text.utf8))
        }
        .wrapped(by: ConditionalRequestMiddleware())
    }

    @Test("a GET 200 is tagged with a stable ETag")
    func addsETag() async {
        let response = await body("hello").respond(to: get(), body: [])
        let etag = response.head.headerFields[.etag]
        #expect(etag != nil)
        // The same body yields the same tag (deterministic validator).
        let again = await body("hello").respond(to: get(), body: [])
        #expect(again.head.headerFields[.etag] == etag)
    }

    @Test("a matching If-None-Match collapses to 304 with no body (RFC 9110 §15.4.5)")
    func notModified() async {
        let first = await body("cached payload").respond(to: get(), body: [])
        let etag = try? #require(first.head.headerFields[.etag])
        let second = await body("cached payload").respond(
            to: get(ifNoneMatch: etag ?? ""), body: [])
        #expect(second.head.status == .notModified)
        #expect(second.body.isEmpty)
        #expect(second.head.headerFields[.etag] == etag)
    }

    @Test("a non-matching If-None-Match returns the full response")
    func staleValidator() async {
        let response = await body("fresh").respond(to: get(ifNoneMatch: "\"stale\""), body: [])
        #expect(response.head.status == .ok)
        #expect(response.body == Array("fresh".utf8))
    }

    @Test("If-None-Match: * matches any current representation (RFC 9110 §13.1.2)")
    func wildcard() async {
        let response = await body("anything").respond(to: get(ifNoneMatch: "*"), body: [])
        #expect(response.head.status == .notModified)
    }

    @Test("the weak prefix is ignored in comparison (RFC 9110 §8.8.3)")
    func weakComparison() async {
        let first = await body("weak").respond(to: get(), body: [])
        let etag = first.head.headerFields[.etag] ?? ""
        let weak = "W/\(etag)"
        let response = await body("weak").respond(to: get(ifNoneMatch: weak), body: [])
        #expect(response.head.status == .notModified)
    }

    @Test("a non-200 response is not tagged")
    func skipsErrors() async {
        let response = await body("error", status: .internalServerError).respond(
            to: get(), body: [])
        #expect(response.head.headerFields[.etag] == nil)
    }

    private func get(ifNoneMatch: String? = nil) -> HTTPRequest {
        var fields = HTTPFields()
        if let ifNoneMatch { _ = fields.append(ifNoneMatch, for: .ifNoneMatch) }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields)
    }
}
