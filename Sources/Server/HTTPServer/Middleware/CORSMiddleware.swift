//
//  CORSMiddleware.swift
//  HTTPServer
//
//  Cross-Origin Resource Sharing (WHATWG Fetch). A request-inspecting, optionally short-circuiting
//  middleware: a CORS preflight (an `OPTIONS` carrying `Access-Control-Request-Method`) is answered
//  directly with `204` and the allow-headers; every other response is decorated with
//  `Access-Control-Allow-Origin`. Configuration is a value type, so a consumer tunes or replaces it.
//

public import HTTPCore

/// Applies CORS headers and answers CORS preflights (WHATWG Fetch / RFC 6454).
public struct CORSMiddleware: HTTPMiddleware {
    /// Which origins are permitted to read responses cross-origin.
    public enum AllowedOrigin: Sendable {
        /// Any origin (`Access-Control-Allow-Origin: *`). A wildcard is always credential-free: pairing
        /// `*` (or a reflected arbitrary origin) with credentials is a total cross-origin bypass
        /// (CWE-942), so ``CORSMiddleware`` suppresses credentials for this case (Fetch §3.2.5).
        case any

        /// A single fixed origin (credentials permitted).
        case exact(String)

        /// An allow-list: the request `Origin` is reflected (with `Vary: Origin`) only when it exactly
        /// matches one of these, and otherwise denied — the safe way to do credentialed multi-origin
        /// CORS.
        case allowList([String])
    }

    private let allowedOrigin: AllowedOrigin
    private let allowedMethods: [HTTPMethod]
    private let allowedHeaders: [String]
    private let allowCredentials: Bool
    private let maxAge: Int?

    /// Creates the middleware with the origins, methods, and headers to permit cross-origin.
    public init(
        allowedOrigin: AllowedOrigin = .any,
        allowedMethods: [HTTPMethod] = [.get, .head, .post, .put, .patch, .delete, .options],
        allowedHeaders: [String] = ["content-type", "authorization"],
        allowCredentials: Bool = false,
        maxAge: Int? = nil
    ) {
        self.allowedOrigin = allowedOrigin
        self.allowedMethods = allowedMethods
        self.allowedHeaders = allowedHeaders
        self.allowCredentials = allowCredentials
        self.maxAge = maxAge
    }

    /// Answers a preflight directly, or decorates the delegated response with CORS headers.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        let origin = request.headerFields[.origin]
        // A preflight is an OPTIONS request carrying Access-Control-Request-Method (Fetch §4.8).
        if request.method == .options, request.headerFields.contains(.accessControlRequestMethod) {
            var head = HTTPResponse(status: .noContent)
            decorate(&head, origin: origin, preflight: true)
            return ServerResponse(head)
        }
        var response = await next.respond(to: request, body: body)
        decorate(&response.head, origin: origin, preflight: false)
        return response
    }

    private func decorate(_ head: inout HTTPResponse, origin: String?, preflight: Bool) {
        let resolved = resolveOrigin(for: origin)
        if let value = resolved.value {
            _ = head.headerFields.setValue(value, for: .accessControlAllowOrigin)
        }
        if resolved.varyOnOrigin {
            // The allow-origin value depends on the request `Origin`, so a shared cache MUST key on it
            // — otherwise one origin's response (and its CORS grant) is served to another (CWE-942).
            appendVaryOrigin(&head)
        }
        if resolved.credentials {
            _ = head.headerFields.setValue("true", for: .accessControlAllowCredentials)
        }
        guard preflight else {
            return
        }
        _ = head.headerFields.setValue(
            allowedMethods.map(\.rawValue).joined(separator: ", "), for: .accessControlAllowMethods
        )
        _ = head.headerFields.setValue(
            allowedHeaders.joined(separator: ", "), for: .accessControlAllowHeaders
        )
        if let maxAge {
            _ = head.headerFields.setValue(String(maxAge), for: .accessControlMaxAge)
        }
    }

    /// Resolves the `Access-Control-Allow-Origin` value (or nil to omit it), whether the response
    /// varies by `Origin`, and whether credentials may be granted — failing safe on the dangerous
    /// wildcard-with-credentials combination (CWE-942).
    private func resolveOrigin(
        for origin: String?
    ) -> (value: String?, varyOnOrigin: Bool, credentials: Bool) {
        switch allowedOrigin {
            case .any:
                // A wildcard can never carry credentials (Fetch §3.2.5); reflecting an arbitrary origin
                // with credentials is a total bypass — so `.any` is always a credential-free `*`.
                ("*", false, false)
            case .exact(let value):
                (value, false, allowCredentials)
            case .allowList(let origins):
                if let origin, origins.contains(origin) {
                    (origin, true, allowCredentials)
                }
                else {
                    (nil, true, false)
                }
        }
    }

    /// Appends `Origin` to `Vary` unless it is already present (RFC 9110 §12.5.5).
    private func appendVaryOrigin(_ head: inout HTTPResponse) {
        let alreadyVaries = head.headerFields.values(for: .vary)
            .contains { $0.lowercased().contains("origin") }
        guard !alreadyVaries else {
            return
        }
        _ = head.headerFields.append("Origin", for: .vary)
    }
}
