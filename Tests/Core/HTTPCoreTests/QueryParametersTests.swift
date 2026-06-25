//
//  QueryParametersTests.swift
//  HTTPCoreTests
//
//  RFC 3986 §3.4 — query-component parsing with percent-decoding, plus the `HTTPRequest.query` /
//  `.cookies` ergonomic accessors. The decoder is lenient (a bad `%XX` stays literal) and must never
//  trap on attacker-controlled input.
//

import Testing

@testable import HTTPCore

@Suite("RFC 3986 §3.4 — query parameters")
struct QueryParametersTests {
    @Test("parses name=value pairs from a target's query")
    func parsesPairs() {
        let query = QueryParameters.parse("/search?q=swift&page=2")
        #expect(query["q"] == "swift")
        #expect(query["page"] == "2")
        #expect(query["missing"] == nil)
    }

    @Test("a target with no query is empty")
    func noQuery() {
        #expect(QueryParameters.parse("/path") == QueryParameters())
    }

    @Test("percent-decodes names and values, and maps + to space (RFC 3986 §2.1)")
    func percentDecodes() {
        let query = QueryParameters.parse("/x?name=a%20b+c&caf%C3%A9=%F0%9F%91%8D")
        #expect(query["name"] == "a b c")
        #expect(query["café"] == "👍")
    }

    @Test("a malformed %XX escape is left literal, never trapping (lenient)")
    func malformedEscapeIsLiteral() {
        let query = QueryParameters.parse("/x?a=100%&b=%zz&c=%")
        #expect(query["a"] == "100%")
        #expect(query["b"] == "%zz")
        #expect(query["c"] == "%")
    }

    @Test("a valueless flag reads as an empty string")
    func valuelessFlag() {
        let query = QueryParameters.parse("/x?debug&y=1")
        #expect(query["debug"]?.isEmpty == true)
        #expect(query["y"] == "1")
    }

    @Test("stops at a fragment and ignores empty pairs")
    func stopsAtFragmentAndSkipsEmpty() {
        let query = QueryParameters.parse("/x?a=1&&b=2#frag=3")
        #expect(query["a"] == "1")
        #expect(query["b"] == "2")
        #expect(query["frag"] == nil)
    }

    @Test("dynamic-member access mirrors the subscript")
    func dynamicMember() {
        let query = QueryParameters.parse("/x?page=7")
        #expect(query.page == "7")
        #expect(query.nope == nil)
    }

    @Test("HTTPRequest.query parses the request target")
    func requestQueryAccessor() {
        let request = HTTPRequest(method: .get, path: "/items?id=42&sort=asc")
        #expect(request.query["id"] == "42")
        #expect(request.query.sort == "asc")
    }

    @Test("HTTPRequest.cookies parses the Cookie header (RFC 6265bis §4.2)")
    func requestCookiesAccessor() {
        var fields = HTTPFields()
        _ = fields.append("session=abc; theme=dark", for: .cookie)
        let request = HTTPRequest(method: .get, path: "/", headerFields: fields)
        #expect(request.cookies["session"] == "abc")
        #expect(request.cookies["theme"] == "dark")
    }
}
