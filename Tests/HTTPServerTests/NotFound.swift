//
//  NotFound.swift
//  HTTPServerTests
//
//  Drives the server's WebSocket integration over an in-memory FakeConnection (RFC 6455 §4): an
//  HTTP/1.1 Upgrade request plus a masked text frame go in; a 101 Switching Protocols response with
//  the correct Sec-WebSocket-Accept and an echoed text frame must come back — proving the handshake
//  and the connection driver without a socket.
//

import HTTPCore

@testable import HTTPServer

/// A responder that always 404s — the WebSocket path never reaches it, so it is just a placeholder.
struct NotFound: HTTPResponder {
    func respond(to _: HTTPRequest, body _: [UInt8]) async -> ServerResponse {
        ServerResponse(HTTPResponse(status: .notFound))
    }
}
