//
//  BasicAuthTests.swift
//  HTTPAuthTests
//
//  RFC 7617 — the right credential is accepted (and the username asserted on `.xAuthSubject`); a wrong or
//  absent credential is a `401` carrying the `WWW-Authenticate: Basic realm="…"` challenge.
//

import HTTPAuth
import HTTPCore
import HTTPServer
import Testing

@Suite("HTTPAuth — Basic authentication (RFC 7617)")
struct BasicAuthTests {
    @Test("accepts the right credential and asserts the username for the handler")
    func accepts() async {
        let middleware = BasicAuthMiddleware(username: "alice", password: "s3cret")
        let response = await AuthHarness.run(
            middleware, authorization: AuthHarness.basicHeader("alice:s3cret")
        )
        #expect(response.head.status.code == 200)
        #expect(response.head.headerFields[.xAuthSubject] == "alice")
    }

    @Test("rejects a wrong password with 401 + the Basic challenge")
    func rejectsWrongPassword() async {
        let middleware = BasicAuthMiddleware(
            realm: "Area 51",
            username: "alice",
            password: "s3cret"
        )
        let response = await AuthHarness.run(
            middleware, authorization: AuthHarness.basicHeader("alice:nope")
        )
        #expect(response.head.status.code == 401)
        #expect(
            response.head.headerFields[.wwwAuthenticate]?.contains("Basic realm=\"Area 51\"")
                == true
        )
        #expect(response.head.headerFields[.xAuthSubject] == nil)
    }

    @Test("a missing Authorization header is 401")
    func missing() async {
        let middleware = BasicAuthMiddleware(username: "alice", password: "s3cret")
        let response = await AuthHarness.run(middleware, authorization: nil)
        #expect(response.head.status.code == 401)
    }

    @Test("a non-Basic scheme is rejected")
    func wrongScheme() async {
        let middleware = BasicAuthMiddleware(username: "alice", password: "s3cret")
        let response = await AuthHarness.run(middleware, authorization: "Bearer abc")
        #expect(response.head.status.code == 401)
    }
}
