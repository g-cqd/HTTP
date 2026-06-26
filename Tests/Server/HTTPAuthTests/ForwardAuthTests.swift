//
//  ForwardAuthTests.swift
//  HTTPAuthTests
//
//  The forward-auth escape hatch: an allow verdict propagates the chosen headers downstream and continues;
//  a deny verdict returns the authorizer's terminal response without invoking the handler.
//

import HTTPAuth
import HTTPCore
import HTTPServer
import Testing

@Suite("HTTPAuth — forward auth")
struct ForwardAuthTests {
    @Test("allow propagates the chosen headers and continues to the handler")
    func allow() async {
        let middleware = ForwardAuthMiddleware { _ in .allow(headers: [(.xAuthSubject, "dave")]) }
        let response = await AuthHarness.run(middleware)
        #expect(response.head.status.code == 200)
        #expect(response.head.headerFields[.xAuthSubject] == "dave")  // propagated downstream
    }

    @Test("deny returns the authorizer's terminal response")
    func deny() async {
        let denied = ServerResponse(HTTPResponse(status: .forbidden))
        let middleware = ForwardAuthMiddleware { _ in .deny(denied) }
        let response = await AuthHarness.run(middleware)
        #expect(response.head.status.code == 403)
        #expect(response.head.headerFields[.xAuthSubject] == nil)  // handler never reached
    }
}
