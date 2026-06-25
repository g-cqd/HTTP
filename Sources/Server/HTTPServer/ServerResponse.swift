//
//  ServerResponse.swift
//  HTTPServer
//
//  What a responder returns: the status/header message (RFC 9110 §3) and its body — either buffered
//  bytes (the common case) or an incremental ``ResponseStream`` the engine pumps to the wire. The
//  buffered `body` stays a plain `[UInt8]` so existing middleware and handlers are unchanged; `stream`
//  is opt-in and, when set, the engine streams it and ignores `body`.
//

public import HTTPCore

/// A response to send back: the status/header message (RFC 9110 §3) and a buffered or streamed body.
public struct ServerResponse: Sendable, Equatable {
    /// The response head (status + header fields).
    public var head: HTTPResponse

    /// The buffered response body (ignored when ``stream`` is set).
    public var body: [UInt8]

    /// An incremental body producer; when set, the engine streams it and ignores ``body``.
    public var stream: ResponseStream?

    /// Creates a response from a head and (optionally) a buffered body.
    public init(_ head: HTTPResponse, body: [UInt8] = []) {
        self.head = head
        self.body = body
        self.stream = nil
    }

    /// Creates a streaming response: the engine pumps `stream` to the wire (HTTP/1.1 frames it chunked).
    public init(_ head: HTTPResponse, stream: ResponseStream) {
        self.head = head
        self.body = []
        self.stream = stream
    }

    /// Compares buffered responses by head and body; a streamed body is an opaque producer, so any
    /// response carrying one compares unequal (Equatable is exercised only on buffered-body responses).
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.head == rhs.head && lhs.body == rhs.body && lhs.stream == nil && rhs.stream == nil
    }
}
