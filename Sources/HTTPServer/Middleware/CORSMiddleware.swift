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
        /// Any origin (`Access-Control-Allow-Origin: *`); echoes the request origin when credentials
        /// are allowed, since `*` is invalid with credentials (Fetch §3.2.5).
        case any

        /// A single fixed origin.
        case exact(String)
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
        _ = head.headerFields.setValue(allowOrigin(for: origin), for: .accessControlAllowOrigin)
        if allowCredentials {
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

    private func allowOrigin(for origin: String?) -> String {
        switch allowedOrigin {
            case .exact(let value):
                value
            case .any:
                allowCredentials ? (origin ?? "*") : "*"
        }
    }
}
