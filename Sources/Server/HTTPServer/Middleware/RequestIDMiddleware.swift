//
//  RequestIDMiddleware.swift
//  HTTPServer
//
//  A per-request correlation id (the `X-Request-ID` convention). The middleware reuses a valid inbound
//  id (so a front proxy's id flows through) or mints a fresh 128-bit random one, asserts it onto the
//  request for downstream handlers and the access log, and echoes it on the response. An inbound id is
//  validated to visible-ASCII before it is trusted, so a hostile value cannot smuggle control bytes into
//  a log line; the request value is always replaced, never appended.
//

public import HTTPCore

/// Stamps a per-request correlation id (`X-Request-ID`) onto the request and the response.
public struct RequestIDMiddleware: HTTPMiddleware {
    private let field: HTTPFieldName
    private let trustInbound: Bool
    private let generate: @Sendable () -> String

    /// Creates the middleware.
    ///
    /// `trustInbound` reuses a syntactically valid inbound id (correlation across a proxy); set it
    /// false to always mint a fresh id. `generate` defaults to a 128-bit random hex token.
    public init(
        field: HTTPFieldName = .xRequestID,
        trustInbound: Bool = true,
        generate: @escaping @Sendable () -> String = Self.randomID
    ) {
        self.field = field
        self.trustInbound = trustInbound
        self.generate = generate
    }

    /// Resolves the id, asserts it on the request, delegates, and echoes it on the response.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        let id = resolvedID(request)
        var request = request
        _ = request.headerFields.setValue(id, for: field)  // server-asserted: replaces any inbound
        // Surface the resolved id on the context too, so handlers and the access log read a guaranteed
        // correlation id from `context.id` (the server itself does not mint one on the hot path).
        var context = context
        context.id = id
        var response = await next.respond(to: request, body: body, context: context)
        _ = response.head.headerFields.setValue(id, for: field)
        return response
    }

    /// A valid inbound id (when trusted), else a freshly generated one.
    private func resolvedID(_ request: HTTPRequest) -> String {
        if trustInbound, let inbound = request.headerFields[field], Self.isValid(inbound) {
            return inbound
        }
        return generate()
    }

    /// Whether `id` is a safe correlation token: non-empty, bounded, and visible ASCII (no controls).
    static func isValid(_ id: String) -> Bool {
        !id.isEmpty && id.count <= 200 && id.utf8.allSatisfy { (0x21 ... 0x7e).contains($0) }
    }

    /// A 128-bit random hex token (`SystemRandomNumberGenerator`).
    public static func randomID() -> String {
        var rng = SystemRandomNumberGenerator()
        let high = UInt64.random(in: .min ... .max, using: &rng)
        let low = UInt64.random(in: .min ... .max, using: &rng)
        return String(high, radix: 16) + String(low, radix: 16)
    }
}
