//
//  SecurityHeadersMiddleware.swift
//  HTTPServer
//
//  Adds the common hardening response headers (each only if the responder did not set it): MIME-sniff
//  protection, clickjacking/framing policy, referrer policy, and optionally HSTS (RFC 6797) and a
//  Content-Security-Policy. All are configurable, since the right values are deployment-specific.
//

public import HTTPCore

/// Stamps security response headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
/// and optionally `Strict-Transport-Security` / `Content-Security-Policy`).
public struct SecurityHeadersMiddleware: HTTPMiddleware {
    private let contentTypeOptions: Bool
    private let frameOptions: String?
    private let referrerPolicy: String?
    private let strictTransportSecurity: String?
    private let contentSecurityPolicy: String?

    /// Creates the middleware. `strictTransportSecurity` is off by default (it only applies over
    /// HTTPS and must not be sent on cleartext); pass e.g. `"max-age=31536000; includeSubDomains"`.
    public init(
        contentTypeOptions: Bool = true,
        frameOptions: String? = "DENY",
        referrerPolicy: String? = "no-referrer",
        strictTransportSecurity: String? = nil,
        contentSecurityPolicy: String? = nil
    ) {
        self.contentTypeOptions = contentTypeOptions
        self.frameOptions = frameOptions
        self.referrerPolicy = referrerPolicy
        self.strictTransportSecurity = strictTransportSecurity
        self.contentSecurityPolicy = contentSecurityPolicy
    }

    /// Delegates, then stamps each configured header that the responder did not already set.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body)
        if contentTypeOptions { setIfAbsent("nosniff", .xContentTypeOptions, &response) }
        setIfAbsent(frameOptions, .xFrameOptions, &response)
        setIfAbsent(referrerPolicy, .referrerPolicy, &response)
        setIfAbsent(strictTransportSecurity, .strictTransportSecurity, &response)
        setIfAbsent(contentSecurityPolicy, .contentSecurityPolicy, &response)
        return response
    }

    private func setIfAbsent(
        _ value: String?, _ name: HTTPFieldName, _ response: inout ServerResponse
    ) {
        guard let value, !response.head.headerFields.contains(name) else {
            return
        }
        _ = response.head.headerFields.append(value, for: name)
    }
}
