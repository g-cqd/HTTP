//
//  HTTP3Error+HTTPProtocolError.swift
//  HTTP3
//
//  Phase 3.4 — `HTTP3Error` as a unified ``HTTPProtocolError``. It already carries `reason` and
//  `isConnectionError` (the connection-vs-stream scope, RFC 9114 §8); only the version is added.
//

public import HTTPCore

extension HTTP3Error: HTTPProtocolError {
    /// Always ``HTTPProtocolVersion/http3``.
    public var httpProtocol: HTTPProtocolVersion { .http3 }
}
