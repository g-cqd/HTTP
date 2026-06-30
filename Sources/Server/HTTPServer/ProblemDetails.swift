//
//  ProblemDetails.swift
//  HTTPServer
//
//  RFC 9457 — Problem Details for HTTP APIs. A machine-readable error body carried as
//  `application/problem+json`: a problem `type` (a URI reference identifying the problem kind,
//  defaulting to `"about:blank"`), a short human-readable `title`, the HTTP `status` code, a
//  request-specific `detail`, and an `instance` URI. A `Codable` value so a client can decode it and a
//  server can build one; ``ServerResponse/problem(_:status:)`` renders it to the wire.
//

/// An RFC 9457 problem-details object: a machine-readable description of an error response.
///
/// The members are exactly the five RFC 9457 §3.1 standard fields. `type` defaults to `"about:blank"`
/// (the "no further information" type, §4.2.1); the other fields are omitted from the JSON when `nil`.
public struct ProblemDetails: Codable, Sendable, Equatable {
    /// A URI reference identifying the problem type (RFC 9457 §3.1.1); `"about:blank"` means "no type".
    public var type: String

    /// A short, human-readable summary of the problem type (RFC 9457 §3.1.2).
    public var title: String?

    /// The HTTP status code for this occurrence (RFC 9457 §3.1.3).
    public var status: Int?

    /// A human-readable explanation specific to this occurrence (RFC 9457 §3.1.4).
    public var detail: String?

    /// A URI reference identifying the specific occurrence (RFC 9457 §3.1.5).
    public var instance: String?

    /// Creates a problem-details object; `type` defaults to `"about:blank"` and the rest are omitted
    /// from the encoded JSON when left `nil`.
    public init(
        type: String = "about:blank",
        title: String? = nil,
        status: Int? = nil,
        detail: String? = nil,
        instance: String? = nil
    ) {
        self.type = type
        self.title = title
        self.status = status
        self.detail = detail
        self.instance = instance
    }
}
