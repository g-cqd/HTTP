//
//  StubResponder.swift
//  HTTPObservabilityTests
//
//  A terminal responder with a fixed status — the downstream end of a middleware under test, built on
//  the public `HTTPResponder` seam (so the tests need no `@testable` access).
//

import HTTPCore
import HTTPServer

/// A terminal `HTTPResponder` that always returns `status` with an empty body.
struct StubResponder: HTTPResponder {
    let status: HTTPStatus

    func respond(to _: HTTPRequest, body _: [UInt8]) async -> ServerResponse {
        ServerResponse(HTTPResponse(status: status))
    }
}
