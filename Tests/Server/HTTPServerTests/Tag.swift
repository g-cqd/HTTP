//
//  Tag.swift
//  HTTPServerTests
//
//  The middleware abstraction: chain ordering (outermost-first), short-circuiting, and the built-in
//  Server-header, access-log, and CORS middlewares.
//

import HTTPCore

@testable import HTTPServer

/// A middleware that records its name on the way in and out, around `next`.
struct Tag: HTTPMiddleware {
    let name: String
    let recorder: Recorder

    init(_ name: String, _ recorder: Recorder) {
        self.name = name
        self.recorder = recorder
    }
    func respond(
        to request: HTTPRequest, body: [UInt8], next: any HTTPResponder
    ) async
        -> ServerResponse
    {
        recorder.add("\(name)→")
        let response = await next.respond(to: request, body: body)
        recorder.add("→\(name)")
        return response
    }
}
