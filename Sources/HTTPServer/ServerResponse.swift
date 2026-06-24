//
//  ServerResponse.swift
//  HTTPServer
//
//  The request-handling interface the server drives. Deliberately a plain protocol (plus a closure
//  adapter) for now; the result-builder routing DSL will conform to it as a later layer.
//

public import HTTPCore

/// A response to send back: the status/header message (RFC 9110 §3) and its body bytes.
public struct ServerResponse: Sendable, Equatable {
    /// The response head (status + header fields).
    public var head: HTTPResponse

    /// The response body.
    public var body: [UInt8]

    /// Creates a response from a head and (optionally) a body.
    public init(_ head: HTTPResponse, body: [UInt8] = []) {
        self.head = head
        self.body = body
    }
}
