//
//  HTTPProtocolError.swift
//  HTTPCore
//
//  A unified error seam across the protocol versions (Phase 3.4): `HTTP1ParseError`, `HTTP2Error`, and
//  `HTTP3Error` each conform, so a consumer can `catch let error as any HTTPProtocolError` and read the
//  version, a diagnostic, and the connection-vs-stream scope without switching on three concrete types.
//

/// A protocol-level error from any HTTP version's parser or engine (Phase 3.4).
public protocol HTTPProtocolError: Error, Sendable {
    /// The HTTP version whose parser or engine raised this error.
    var httpProtocol: HTTPProtocolVersion { get }

    /// A human-readable diagnostic (never sent on the wire).
    var reason: String { get }

    /// Whether the error is connection-fatal, rather than scoped to a single stream / request.
    var isConnectionError: Bool { get }
}
