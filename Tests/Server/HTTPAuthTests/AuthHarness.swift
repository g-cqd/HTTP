//
//  AuthHarness.swift
//  HTTPAuthTests
//
//  Shared plumbing for the auth-middleware tests: a terminal responder that reflects the verified
//  principal (`.xAuthSubject`) back on the response so a test can assert it was asserted, plus a runner
//  that drives a middleware with a given `Authorization` header.
//

import Foundation
import HTTPCore
import HTTPServer

/// Test plumbing for driving an auth middleware and observing the principal it asserts.
enum AuthHarness {
    /// A terminal responder echoing the request's `.xAuthSubject` onto a `200` response.
    struct EchoResponder: HTTPResponder {
        func respond(
            to request: HTTPRequest, body _: RequestBody, context _: RequestContext
        ) async -> ServerResponse {
            var head = HTTPResponse(status: .ok)
            if let subject = request.headerFields[.xAuthSubject] {
                _ = head.headerFields.setValue(subject, for: .xAuthSubject)
            }
            return ServerResponse(head)
        }
    }

    /// Runs `middleware` over a `GET /` request carrying `authorization` (if any).
    static func run(
        _ middleware: any HTTPMiddleware,
        authorization: String? = nil
    ) async -> ServerResponse {
        var fields = HTTPFields()
        if let authorization {
            _ = fields.append(authorization, for: .authorization)
        }
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        return await middleware.respond(to: request, body: [], next: EchoResponder())
    }

    /// A `Basic` credential header value for `user:pass` (RFC 7617 §2).
    static func basicHeader(_ credential: String) -> String {
        "Basic " + Data(credential.utf8).base64EncodedString()
    }
}
