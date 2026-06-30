//
//  HTTP2Error+HTTPProtocolError.swift
//  HTTP2
//
//  Phase 3.4 — `HTTP2Error` as a unified ``HTTPProtocolError``. It already carries `reason` and
//  `isConnectionError` (the GOAWAY-vs-RST_STREAM scope, RFC 9113 §5.4); only the version is added.
//

public import HTTPCore

extension HTTP2Error: HTTPProtocolError {
    /// Always ``HTTPProtocolVersion/http2``.
    public var httpProtocol: HTTPProtocolVersion { .http2 }
}
