//
//  HTTP1ParseError+HTTPProtocolError.swift
//  HTTP1
//
//  Phase 3.4 — `HTTP1ParseError` as a unified ``HTTPProtocolError``. An HTTP/1.1 parse failure fails the
//  message closed (the server answers, e.g., 400 / 431 / 505, then closes), so it is always
//  connection-scoped; the diagnostic is the case name.
//

public import HTTPCore

extension HTTP1ParseError: HTTPProtocolError {
    /// Always ``HTTPProtocolVersion/http1``.
    public var httpProtocol: HTTPProtocolVersion { .http1 }

    /// The case name as a short diagnostic (e.g. `bodyTooLarge`).
    public var reason: String { String(describing: self) }

    /// Always `true` — an HTTP/1.1 parse error fails the message closed (RFC 9112).
    public var isConnectionError: Bool { true }
}
