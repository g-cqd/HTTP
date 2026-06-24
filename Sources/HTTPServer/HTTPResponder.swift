//
//  HTTPResponder.swift
//  HTTPServer
//
//  The request-handling interface the server drives. Deliberately a plain protocol (plus a closure
//  adapter) for now; the result-builder routing DSL will conform to it as a later layer.
//

public import HTTPCore

/// Produces a ``ServerResponse`` for a parsed request.
///
/// The unit of application logic the server runs; the routing DSL will conform to it later.
public protocol HTTPResponder: Sendable {
    /// Responds to `request` (with its decoded `body`).
    func respond(to request: HTTPRequest, body: [UInt8]) async -> ServerResponse
}
