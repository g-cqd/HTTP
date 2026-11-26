//
//  HTTPClientError.swift
//  HTTPClient
//
//  Every way an outbound exchange fails, typed so callers can tell a network failure (retryable)
//  from a protocol violation or a policy refusal (not).
//

/// The failure of one ``HTTPClient`` exchange.
public enum HTTPClientError: Error, Sendable, Equatable {
    /// The request URL / authority is unusable (scheme, host, or port).
    case invalidRequest(String)
    /// Name resolution or TCP connect failed.
    case connectFailed(String)
    /// The TLS 1.3 handshake failed or the server certificate was rejected.
    case tlsFailed(String)
    /// The peer closed or reset the connection mid-exchange.
    case connectionClosed
    /// The response violated RFC 9112 (status line, headers, or body framing).
    case malformedResponse(String)
    /// The (decoded) response body exceeded the configured bound (CWE-400 / CWE-409).
    case responseTooLarge(limit: Int)
    /// The response used a content coding this client cannot decode, or decoding failed.
    case undecodableBody(String)
    /// The exchange exceeded its deadline.
    case timedOut
    /// A redirect was refused by policy or exceeded the redirect budget.
    case redirectRefused(String)
    /// The caller's task was cancelled.
    case cancelled
}
