//
//  ConditionalRequestMiddlewareTests.swift
//  HTTPServerTests
//
//  Conditional requests (RFC 9110 §13): ETag generation, the §13.2.2 precondition order — If-Match /
//  If-Unmodified-Since → 412, If-None-Match / If-Modified-Since → 304 — and weak vs strong comparison.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — conditional requests (RFC 9110 §13)")
struct ConditionalRequestMiddlewareTests {
    private func body(
        _ text: String,
        status: HTTPStatus = .ok,
        lastModified: Int? = nil
    ) -> any HTTPResponder {
        ClosureResponder { _, _ in
            var head = HTTPResponse(status: status)
            if let lastModified {
                _ = head.headerFields.setValue(
                    HTTPDate.imfFixdate(lastModified), for: .lastModified
                )
            }
            return ServerResponse(head, body: Array(text.utf8))
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
        let etag = first.head.headerFields[.etag]
        #expect(etag != nil)
        let second = await body("cached payload")
            .respond(to: get(ifNoneMatch: etag ?? ""), body: [])
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
        let response = await body("error", status: .internalServerError)
            .respond(to: get(), body: [])
        #expect(response.head.headerFields[.etag] == nil)
    }

    @Test("If-Match with a matching validator serves the full response (RFC 9110 §13.1.1)")
    func ifMatchMatches() async {
        let tagged = await body("payload").respond(to: get(), body: [])
        let etag = tagged.head.headerFields[.etag] ?? ""
        let response = await body("payload").respond(to: get(ifMatch: etag), body: [])
        #expect(response.head.status == .ok)
        #expect(response.body == Array("payload".utf8))
    }

    @Test("If-Match with a stale validator is 412 Precondition Failed (RFC 9110 §13.2.2)")
    func ifMatchFails() async {
        let response = await body("payload").respond(to: get(ifMatch: "\"stale\""), body: [])
        #expect(response.head.status == .preconditionFailed)
        #expect(response.body.isEmpty)
    }

    @Test("If-Match: * matches any current representation")
    func ifMatchWildcard() async {
        #expect(await body("x").respond(to: get(ifMatch: "*"), body: []).head.status == .ok)
    }

    @Test("If-Unmodified-Since is 412 when the representation is newer (RFC 9110 §13.1.4)")
    func ifUnmodifiedSinceFails() async {
        // Last-Modified (2000) is after the If-Unmodified-Since instant (1994) → 412.
        let response = await body("x", lastModified: 951_782_400)
            .respond(to: get(ifUnmodifiedSince: 784_111_777), body: [])
        #expect(response.head.status == .preconditionFailed)
    }

    @Test("If-Unmodified-Since passes when the representation is not newer")
    func ifUnmodifiedSincePasses() async {
        let response = await body("x", lastModified: 784_111_777)
            .respond(to: get(ifUnmodifiedSince: 951_782_400), body: [])
        #expect(response.head.status == .ok)
    }

    @Test("If-Modified-Since collapses an unchanged representation to 304 (RFC 9110 §13.1.3)")
    func ifModifiedSinceNotModified() async {
        // Last-Modified (1994) is at/before the If-Modified-Since instant (2000) → 304.
        let response = await body("x", lastModified: 784_111_777)
            .respond(to: get(ifModifiedSince: 951_782_400), body: [])
        #expect(response.head.status == .notModified)
        #expect(response.head.headerFields[.lastModified] == "Sun, 06 Nov 1994 08:49:37 GMT")
    }

    @Test("If-Modified-Since serves the full response when modified after the date")
    func ifModifiedSinceModified() async {
        let response = await body("fresh", lastModified: 951_782_400)
            .respond(to: get(ifModifiedSince: 784_111_777), body: [])
        #expect(response.head.status == .ok)
        #expect(response.body == Array("fresh".utf8))
    }

    private func get(
        ifNoneMatch: String? = nil,
        ifMatch: String? = nil,
        ifModifiedSince: Int? = nil,
        ifUnmodifiedSince: Int? = nil
    ) -> HTTPRequest {
        var fields = HTTPFields()
        if let ifNoneMatch { _ = fields.append(ifNoneMatch, for: .ifNoneMatch) }
        if let ifMatch { _ = fields.append(ifMatch, for: .ifMatch) }
        if let ifModifiedSince {
            _ = fields.append(HTTPDate.imfFixdate(ifModifiedSince), for: .ifModifiedSince)
        }
        if let ifUnmodifiedSince {
            _ = fields.append(HTTPDate.imfFixdate(ifUnmodifiedSince), for: .ifUnmodifiedSince)
        }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }
}
