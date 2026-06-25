//
//  RangeMiddlewareTests.swift
//  HTTPServerTests
//
//  Range requests (RFC 9110 §14): the byte-range parser (single / suffix / open-ended / unsatisfiable
//  / ignored forms) and the middleware behavior — 206 with Content-Range + sliced body, 416 for a
//  range past the body, Accept-Ranges advertised on a range-able 200, and fail-open to the full 200
//  for multi-range / non-bytes / non-GET.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — Range / 206 Partial Content (RFC 9110 §14)")
struct RangeMiddlewareTests {
    @Test(
        "byte-range parsing covers every single-range form (RFC 9110 §14.1.2)",
        arguments: [
            ("bytes=2-5", 10, RangeMiddleware.ParsedRange.satisfiable(start: 2, end: 5)),
            ("bytes=0-100", 10, .satisfiable(start: 0, end: 9)),  // last clamped to the body
            ("bytes=5-", 10, .satisfiable(start: 5, end: 9)),  // open-ended
            ("bytes=-3", 10, .satisfiable(start: 7, end: 9)),  // suffix: last 3 octets
            ("bytes=-100", 10, .satisfiable(start: 0, end: 9)),  // suffix longer than the body
            ("bytes=10-20", 10, .unsatisfiable),  // first past the body
            ("bytes=20-", 10, .unsatisfiable),
            ("bytes=-0", 10, .ignore),  // zero-length suffix
            ("bytes=5-2", 10, .ignore),  // last < first
            ("bytes=abc", 10, .ignore),  // non-numeric
            ("bytes=0-1,3-4", 10, .ignore),  // multi-range (v1 ignores)
            ("items=0-4", 10, .ignore),  // non-bytes unit
            ("bytes=0-4", 0, .ignore)  // empty body
        ]
    )
    func parse(_ value: String, _ total: Int, _ expected: RangeMiddleware.ParsedRange) {
        #expect(RangeMiddleware.parse(value, total: total) == expected)
    }

    @Test("a satisfiable single range returns 206 with Content-Range and the sliced body")
    func partialContent() async {
        let response = await served("0123456789").respond(to: request(range: "bytes=2-5"), body: [])
        #expect(response.head.status == .partialContent)
        #expect(response.head.headerFields[.contentRange] == "bytes 2-5/10")
        #expect(response.head.headerFields[.acceptRanges] == "bytes")
        #expect(response.body == Array("2345".utf8))
    }

    @Test("a suffix range returns the last N octets")
    func suffixRange() async {
        let response = await served("0123456789").respond(to: request(range: "bytes=-3"), body: [])
        #expect(response.head.status == .partialContent)
        #expect(response.head.headerFields[.contentRange] == "bytes 7-9/10")
        #expect(response.body == Array("789".utf8))
    }

    @Test("a range past the body returns 416 with Content-Range: bytes */total")
    func rangeNotSatisfiable() async {
        let response = await served("0123456789")
            .respond(to: request(range: "bytes=20-30"), body: [])
        #expect(response.head.status == .rangeNotSatisfiable)
        #expect(response.head.headerFields[.contentRange] == "bytes */10")
        #expect(response.body.isEmpty)
    }

    @Test("a 200 GET without Range advertises Accept-Ranges: bytes (RFC 9110 §14.3)")
    func advertisesAcceptRanges() async {
        let response = await served("hello").respond(to: request(), body: [])
        #expect(response.head.status == .ok)
        #expect(response.head.headerFields[.acceptRanges] == "bytes")
        #expect(response.body == Array("hello".utf8))
    }

    @Test("a multi-range request is ignored — the full 200 is served (RFC 9110 §14.2)")
    func multiRangeServesFull() async {
        let response = await served("0123456789")
            .respond(to: request(range: "bytes=0-1,4-5"), body: [])
        #expect(response.head.status == .ok)
        #expect(response.body == Array("0123456789".utf8))
    }

    @Test("Range on a non-GET is not honored (the body is not range-able)")
    func nonGetUnchanged() async {
        let response = await served("0123456789")
            .respond(to: request(range: "bytes=0-4", method: .post), body: [])
        #expect(response.head.status == .ok)
        #expect(response.body == Array("0123456789".utf8))
        #expect(response.head.headerFields[.acceptRanges] == nil)
    }

    private func served(_ text: String, status: HTTPStatus = .ok) -> any HTTPResponder {
        ClosureResponder { _, _ in
            ServerResponse(HTTPResponse(status: status), body: Array(text.utf8))
        }
        .wrapped(by: RangeMiddleware())
    }

    private func request(range: String? = nil, method: HTTPMethod = .get) -> HTTPRequest {
        var fields = HTTPFields()
        if let range { _ = fields.append(range, for: .range) }
        return HTTPRequest(
            method: method, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }
}
