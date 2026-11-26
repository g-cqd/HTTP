//
//  HTTPClientResponse.swift
//  HTTPClient
//

public import HTTPCore

/// A complete, content-decoded HTTP response.
public struct HTTPClientResponse: Sendable, Equatable {
    /// The final response status (after any followed redirects).
    public let status: HTTPStatus
    /// The final response header fields.
    public let headerFields: HTTPFields
    /// The response body with any `Content-Encoding` removed.
    public let body: [UInt8]

    /// Creates a response.
    public init(status: HTTPStatus, headerFields: HTTPFields, body: [UInt8]) {
        self.status = status
        self.headerFields = headerFields
        self.body = body
    }
}
