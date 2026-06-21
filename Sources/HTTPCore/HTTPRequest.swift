//
//  HTTPRequest.swift
//  HTTPCore
//
//  RFC 9110 §3 — an HTTP request message, modeled version-independently (h1/h2/h3).
//

/// An HTTP request message (RFC 9110 §3).
///
/// The components mirror the HTTP/2 and HTTP/3 control data (the `:method`, `:scheme`, `:authority`,
/// and `:path` pseudo-headers, RFC 9113 §8.3.1) so the same value represents a request on any
/// version. An HTTP/1.1 parser fills `authority` from the `Host` header; HTTP/2 and HTTP/3 fill it
/// from `:authority`.
public struct HTTPRequest: Sendable, Equatable {

    /// The request method (RFC 9110 §9).
    public var method: HTTPMethod

    /// The URI scheme (the `:scheme` pseudo-header), e.g. `"https"`, if known.
    public var scheme: String?

    /// The authority (the `:authority` pseudo-header), e.g. `"example.com:443"`, if known.
    public var authority: String?

    /// The request target in origin form (the `:path` pseudo-header), e.g. `"/index.html?q=1"`.
    public var path: String

    /// The header fields (RFC 9110 §5).
    public var headerFields: HTTPFields

    /// Creates a request from its components.
    public init(
        method: HTTPMethod,
        scheme: String? = nil,
        authority: String? = nil,
        path: String,
        headerFields: HTTPFields = HTTPFields()
    ) {
        self.method = method
        self.scheme = scheme
        self.authority = authority
        self.path = path
        self.headerFields = headerFields
    }

    /// The effective request authority (RFC 9110 §7.2).
    ///
    /// Prefers the `:authority` control data; when it is absent (the HTTP/1.1 case) it falls back to
    /// the `Host` header field. `nil` only if neither is present.
    public var effectiveAuthority: String? {
        authority ?? headerFields[.host]
    }
}
