//
//  HTTPResponse.swift
//  HTTPCore
//
//  RFC 9110 §3 / §15 — an HTTP response message, modeled version-independently (h1/h2/h3).
//

/// An HTTP response message (RFC 9110 §3).
///
/// Carries a ``HTTPStatus`` (the `:status` pseudo-header on HTTP/2 and HTTP/3, or the status-line
/// code on HTTP/1.1) and its header fields. The same value serializes onto any HTTP version.
public struct HTTPResponse: Sendable, Equatable {
    /// The response status code (RFC 9110 §15).
    public var status: HTTPStatus

    /// The header fields (RFC 9110 §5).
    public var headerFields: HTTPFields

    /// Creates a response from a status and (optionally) its header fields.
    public init(status: HTTPStatus, headerFields: HTTPFields = .empty) {
        self.status = status
        self.headerFields = headerFields
    }
}
