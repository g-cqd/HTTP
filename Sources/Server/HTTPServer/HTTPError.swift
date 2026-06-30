//
//  HTTPError.swift
//  HTTPServer
//
//  A throwable HTTP error (RFC 9110 status + RFC 9457 problem fields). A handler can `throw` one from a
//  ``ThrowingResponder`` and have it mapped to an `application/problem+json` response, or build the
//  response directly with ``ServerResponse/problem(_:)``. It carries the status plus the optional
//  problem `type`/`title`/`detail`, so the rendered problem document is fully described by the error.
//

public import HTTPCore

/// A throwable HTTP error carrying a status and RFC 9457 problem fields.
public struct HTTPError: Error, Sendable, Equatable {
    /// The HTTP status code to respond with (RFC 9110 §15).
    public var status: HTTPStatus

    /// A human-readable explanation specific to this occurrence (RFC 9457 §3.1.4), or `nil`.
    public var detail: String?

    /// A URI reference identifying the problem type (RFC 9457 §3.1.1); `"about:blank"` means "no type".
    public var type: String

    /// A short, human-readable summary of the problem type (RFC 9457 §3.1.2); `nil` omits it.
    public var title: String?

    /// Creates an HTTP error for `status`, with optional problem `detail`/`type`/`title`.
    public init(
        _ status: HTTPStatus,
        detail: String? = nil,
        type: String = "about:blank",
        title: String? = nil
    ) {
        self.status = status
        self.detail = detail
        self.type = type
        self.title = title
    }

    /// The RFC 9457 problem-details object describing this error (its `status` is the numeric code).
    public var problemDetails: ProblemDetails {
        ProblemDetails(
            type: type, title: title, status: Int(status.code), detail: detail
        )
    }
}
