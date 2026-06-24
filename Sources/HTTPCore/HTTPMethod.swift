//
//  HTTPMethod.swift
//  HTTPCore
//
//  RFC 9110 §9 — Methods.
//

/// An HTTP request method (RFC 9110 §9).
///
/// The method token is a case-sensitive `token` (RFC 9110 §9.1): `GET` and `get` are distinct.
/// Construction validates the token grammar, so an `HTTPMethod` can never hold a value that would
/// be illegal on the wire. Common methods are available as constants (e.g. ``get``); any other
/// valid token (such as `PROPFIND`) can be created with ``init(rawValue:)``.
public struct HTTPMethod: Sendable, Hashable, RawRepresentable {
    /// The method token, guaranteed to satisfy the RFC 9110 §5.6.2 `token` grammar.
    public let rawValue: String

    /// Creates a method from a token, returning `nil` if `rawValue` is not a valid `token`.
    public init?(rawValue: String) {
        guard FieldValidation.isToken(rawValue.utf8) else { return nil }
        self.rawValue = rawValue
    }

    /// Creates a method from a token already known to be valid (used for the registered constants).
    @usableFromInline
    init(unchecked rawValue: String) {
        self.rawValue = rawValue
    }
}

extension HTTPMethod {
    /// `GET` (RFC 9110 §9.3.1).
    public static let get = HTTPMethod(unchecked: "GET")
    /// `HEAD` (RFC 9110 §9.3.2).
    public static let head = HTTPMethod(unchecked: "HEAD")
    /// `POST` (RFC 9110 §9.3.3).
    public static let post = HTTPMethod(unchecked: "POST")
    /// `PUT` (RFC 9110 §9.3.4).
    public static let put = HTTPMethod(unchecked: "PUT")
    /// `DELETE` (RFC 9110 §9.3.5).
    public static let delete = HTTPMethod(unchecked: "DELETE")
    /// `CONNECT` (RFC 9110 §9.3.6).
    public static let connect = HTTPMethod(unchecked: "CONNECT")
    /// `OPTIONS` (RFC 9110 §9.3.7).
    public static let options = HTTPMethod(unchecked: "OPTIONS")
    /// `TRACE` (RFC 9110 §9.3.8).
    public static let trace = HTTPMethod(unchecked: "TRACE")
    /// `PATCH` (RFC 5789).
    public static let patch = HTTPMethod(unchecked: "PATCH")
}

extension HTTPMethod {
    /// Whether the method is "safe" — essentially read-only semantics (RFC 9110 §9.2.1).
    ///
    /// The registered safe methods are `GET`, `HEAD`, `OPTIONS`, and `TRACE`. Unknown/custom
    /// methods are treated as unsafe (the conservative default).
    public var isSafe: Bool {
        switch self {
            case .get, .head, .options, .trace: true
            default: false
        }
    }

    /// Whether the method is idempotent (RFC 9110 §9.2.2).
    ///
    /// Every safe method is idempotent; additionally `PUT` and `DELETE` are idempotent. Unknown/
    /// custom methods are treated as non-idempotent (the conservative default).
    public var isIdempotent: Bool {
        switch self {
            case .put, .delete: true
            default: isSafe
        }
    }
}
