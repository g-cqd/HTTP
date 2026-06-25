//
//  RequestIDMiddlewareTests.swift
//  HTTPServerTests
//
//  Request correlation (X-Request-ID): minting when absent, propagating a valid inbound id, replacing
//  an unsafe one, and not trusting inbound when configured. The echo responder reflects the request
//  headers so a test can see the id asserted onto the request, and the response echoes it.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — request id (X-Request-ID)")
struct RequestIDMiddlewareTests {
    private let echo = ClosureResponder { request, _ in
        ServerResponse(HTTPResponse(status: .ok, headerFields: request.headerFields))
    }

    private func get(requestID: String? = nil) -> HTTPRequest {
        var fields = HTTPFields()
        if let requestID { _ = fields.append(requestID, for: .xRequestID) }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }

    @Test("mints an id when none is present, on the request and the response")
    func mintsID() async {
        let middleware = RequestIDMiddleware { "fixed-id" }
        let response = await middleware.respond(to: get(), body: [], next: echo)
        #expect(response.head.headerFields[.xRequestID] == "fixed-id")
    }

    @Test("propagates a valid inbound id (correlation across a proxy)")
    func propagates() async {
        let middleware = RequestIDMiddleware { "minted" }
        let response = await middleware.respond(to: get(requestID: "abc-123"), body: [], next: echo)
        #expect(response.head.headerFields[.xRequestID] == "abc-123")
    }

    @Test("replaces an unsafe inbound id (e.g. one containing a space)")
    func replacesUnsafe() async {
        let middleware = RequestIDMiddleware { "minted" }
        let response = await middleware.respond(
            to: get(requestID: "has space"), body: [], next: echo
        )
        #expect(response.head.headerFields[.xRequestID] == "minted")
    }

    @Test("does not trust an inbound id when configured")
    func untrusted() async {
        let middleware = RequestIDMiddleware(trustInbound: false) { "minted" }
        let response = await middleware.respond(to: get(requestID: "abc-123"), body: [], next: echo)
        #expect(response.head.headerFields[.xRequestID] == "minted")
    }
}
