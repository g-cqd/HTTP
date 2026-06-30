//
//  JWTMiddleware.swift
//  HTTPAuth
//
//  RFC 6750 — Bearer token authentication. Extracts the `Authorization: Bearer <jwt>` token and verifies
//  it with the configured ``JWT/Key`` (+ optional audience/issuer) via ``JWT/verify(_:key:audience:issuer:
//  now:leeway:)``; on success the `sub` claim is asserted on `.xAuthSubject` for the handler. A missing or
//  invalid token gets a `401` with `WWW-Authenticate: Bearer error="invalid_token"`. The token is never
//  logged.
//

internal import Foundation
public import HTTPCore
public import HTTPServer

/// Gates requests behind a verified JWT Bearer token (RFC 6750), asserting `sub` on `.xAuthSubject`.
public struct JWTMiddleware: HTTPMiddleware {
    /// The default clock: the current wall-clock time in epoch seconds (keeps `Foundation` internal).
    public static let systemNow: @Sendable () -> Double = { Date().timeIntervalSince1970 }

    private let key: JWT.Key
    private let audience: String?
    private let issuer: String?
    private let leeway: Double
    private let now: @Sendable () -> Double

    /// Creates the middleware verifying tokens against `key`, requiring `audience`/`issuer` when given.
    ///
    /// `now` supplies the current epoch seconds (defaults to wall-clock); `leeway` tolerates clock skew.
    public init(
        key: JWT.Key,
        audience: String? = nil,
        issuer: String? = nil,
        leeway: Double = 0,
        now: @escaping @Sendable () -> Double = Self.systemNow
    ) {
        self.key = key
        self.audience = audience
        self.issuer = issuer
        self.leeway = leeway
        self.now = now
    }

    /// Verifies the Bearer token, asserts `sub` for the handler, else challenges with `401`.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        guard let token = Self.bearerToken(request) else {
            return challenge()
        }
        let result = JWT.verify(
            token, key: key, audience: audience, issuer: issuer, now: now(), leeway: leeway
        )
        guard case .success(let claims) = result else {
            return challenge()
        }
        var request = request
        if let subject = claims.subject {
            _ = request.headerFields.setValue(subject, for: .xAuthSubject)
        }
        return await next.respond(to: request, body: body, context: context)
    }

    /// A `401` carrying the `Bearer` challenge (RFC 6750 §3).
    private func challenge() -> ServerResponse {
        var head = HTTPResponse(status: .unauthorized)
        _ = head.headerFields.setValue("Bearer error=\"invalid_token\"", for: .wwwAuthenticate)
        return ServerResponse(head)
    }

    /// The token from `Authorization: Bearer <token>` (RFC 6750 §2.1), or nil.
    ///
    /// Returns the borrowed `Substring` — `JWT.verify` takes `some StringProtocol`, so the token reaches
    /// the verifier with no `String(parts[1])` materialization.
    private static func bearerToken(_ request: HTTPRequest) -> Substring? {
        guard let header = request.headerFields[.authorization] else {
            return nil
        }
        let parts = header.split(separator: " ", maxSplits: 1)
        guard parts.count == 2, parts[0].lowercased() == "bearer" else {
            return nil
        }
        return parts[1]
    }
}
