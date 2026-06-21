//
//  HTTPMethodTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for RFC 9110 §9 methods and their safe/idempotent properties.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §9 — HTTPMethod")
struct HTTPMethodTests {

    @Test("registered constants are upper-case tokens")
    func registeredConstants() {
        #expect(HTTPMethod.get.rawValue == "GET")
        #expect(HTTPMethod.post.rawValue == "POST")
        #expect(HTTPMethod.delete.rawValue == "DELETE")
        #expect(HTTPMethod.patch.rawValue == "PATCH")
    }

    @Test("a token round-trips and equals the matching constant")
    func tokenRoundTrip() {
        #expect(HTTPMethod(rawValue: "GET") == .get)
        #expect(HTTPMethod(rawValue: "PROPFIND")?.rawValue == "PROPFIND")
    }

    @Test("the method token is case-sensitive (RFC 9110 §9.1)")
    func caseSensitive() {
        #expect(HTTPMethod(rawValue: "get") != .get)
    }

    @Test("rejects non-token method names", arguments: ["", "GE T", "G/T", "GET\r", "GÉT"])
    func rejectsNonTokens(_ name: String) {
        #expect(HTTPMethod(rawValue: name) == nil)
    }

    @Test(
        "classifies safe methods (RFC 9110 §9.2.1)",
        arguments: [
            (HTTPMethod.get, true), (.head, true), (.options, true), (.trace, true),
            (.post, false), (.put, false), (.delete, false), (.patch, false), (.connect, false),
        ]
    )
    func safe(_ method: HTTPMethod, _ expected: Bool) {
        #expect(method.isSafe == expected)
    }

    @Test(
        "classifies idempotent methods (RFC 9110 §9.2.2)",
        arguments: [
            (HTTPMethod.get, true), (.head, true), (.options, true), (.trace, true),
            (.put, true), (.delete, true),
            (.post, false), (.patch, false), (.connect, false),
        ]
    )
    func idempotent(_ method: HTTPMethod, _ expected: Bool) {
        #expect(method.isIdempotent == expected)
    }
}
