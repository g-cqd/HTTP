//
//  Blocker.swift
//  HTTPServerTests
//
//  The middleware abstraction: chain ordering (outermost-first), short-circuiting, and the built-in
//  Server-header, access-log, and CORS middlewares.
//

import HTTPCore

@testable import HTTPServer

/// A middleware that short-circuits the chain with `403 Forbidden`.
struct Blocker: HTTPMiddleware {
    func respond(
        to _: HTTPRequest, body _: [UInt8], next _: any HTTPResponder
    ) async
        -> ServerResponse
    {
        ServerResponse(HTTPResponse(status: .forbidden))
    }
}
