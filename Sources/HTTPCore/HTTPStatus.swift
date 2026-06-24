//
//  HTTPStatus.swift
//  HTTPCore
//
//  RFC 9110 §15 — Response Status Codes.
//

/// An HTTP response status code (RFC 9110 §15).
///
/// A status code is a three-digit integer in `100...599`; its first digit names the class of
/// response (``Kind``). Status codes are version-independent: HTTP/1.1 pairs them with an advisory
/// reason-phrase on the status-line, while HTTP/2 and HTTP/3 carry them in the `:status`
/// pseudo-header.
public struct HTTPStatus: Sendable, Hashable {
    /// The numeric status code, guaranteed to be within `100...599`.
    public let code: UInt16

    /// The class of a status code, defined by its first digit (RFC 9110 §15).
    public enum Kind: Sendable, Hashable {
        /// 1xx — the request was received; the process is continuing.
        case informational
        /// 2xx — the request was successfully received, understood, and accepted.
        case successful
        /// 3xx — further action is needed in order to complete the request.
        case redirection
        /// 4xx — the request contains bad syntax or cannot be fulfilled.
        case clientError
        /// 5xx — the server failed to fulfill an apparently valid request.
        case serverError
    }

    /// Creates a status from a numeric code, returning `nil` if it is outside `100...599`.
    public init?(code: Int) {
        guard (100 ... 599).contains(code) else { return nil }
        self.code = UInt16(code)
    }

    /// Creates a status from a code already known to be valid (used for the registered constants).
    @usableFromInline
    init(unchecked code: UInt16) {
        self.code = code
    }

    /// The response class this status belongs to (RFC 9110 §15).
    ///
    /// `code` is an invariant `100...599`, so the five arms below are exhaustive.
    public var kind: Kind {
        switch code {
            case 100 ... 199: .informational
            case 200 ... 299: .successful
            case 300 ... 399: .redirection
            case 400 ... 499: .clientError
            default: .serverError  // 500...599 (code is invariant-bounded to 100...599)
        }
    }
}
