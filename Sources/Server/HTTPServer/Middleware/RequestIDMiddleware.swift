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
        let id = resolvedID(request, context)
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
    ///
    /// `X-Request-ID` is server-asserted, so the server *moves* a valid inbound one off the request
    /// and into ``RequestContext/id`` at ingress (audit CR-F13) — the context is where a front proxy's
    /// id survives, and reading the header alone would have silently turned `trustInbound` into a
    /// no-op. A custom ``field`` is not on that strip list and is still read from the wire.
    private func resolvedID(_ request: HTTPRequest, _ context: RequestContext) -> String {
        guard trustInbound else {
            return generate()
        }
        if let inbound = request.headerFields[field], Self.isValid(inbound) {
            return inbound
        }
        if field == .xRequestID, let lifted = context.id, Self.isValid(lifted) {
            return lifted
        }
        return generate()
    }

    /// Whether `id` is a safe correlation token: non-empty, bounded, and visible ASCII (no controls).
    static func isValid(_ id: String) -> Bool {
        !id.isEmpty && id.count <= 200 && id.utf8.allSatisfy { (0x21 ... 0x7e).contains($0) }
    }

    /// A 128-bit random token as exactly 32 lowercase hex digits (``RandomToken/hex128()``).
    public static func randomID() -> String {
        RandomToken.hex128()
    }
}
