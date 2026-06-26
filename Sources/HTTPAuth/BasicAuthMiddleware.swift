//
//  BasicAuthMiddleware.swift
//  HTTPAuth
//
//  RFC 7617 — HTTP Basic authentication. The `Authorization: Basic base64(user:pass)` credential is
//  verified by an injected closure; a missing or rejected credential gets a `401` with a
//  `WWW-Authenticate: Basic realm="…"` challenge, and the verified username is asserted on `.xAuthSubject`
//  for the handler. Credentials are never logged. The bundled fixed-credential initializer compares in
//  constant time (double-HMAC under an ephemeral key), so a wrong username and a wrong password are
//  indistinguishable by timing.
//

internal import Crypto
internal import Foundation
public import HTTPCore
public import HTTPServer

/// Gates requests behind HTTP Basic credentials (RFC 7617), asserting the username on `.xAuthSubject`.
public struct BasicAuthMiddleware: HTTPMiddleware {
    private let realm: String
    private let verify: @Sendable (_ username: String, _ password: String) -> Bool

    /// Creates the middleware verifying each credential with `verify` (compare in constant time).
    public init(
        realm: String = "Restricted",
        verify: @escaping @Sendable (_ username: String, _ password: String) -> Bool
    ) {
        self.realm = realm
        self.verify = verify
    }

    /// Creates the middleware accepting one fixed credential, compared in constant time.
    public init(realm: String = "Restricted", username: String, password: String) {
        self.init(realm: realm) { candidateUser, candidatePassword in
            let userOK = Self.constantTimeEquals(candidateUser, username)
            let passwordOK = Self.constantTimeEquals(candidatePassword, password)
            return userOK && passwordOK
        }
    }

    /// Verifies the credential, asserts the username for the handler, else challenges with `401`.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        guard let credential = Self.credential(request),
            verify(credential.username, credential.password)
        else {
            return challenge()
        }
        var request = request
        _ = request.headerFields.setValue(credential.username, for: .xAuthSubject)
        return await next.respond(to: request, body: body)
    }

    /// A `401` carrying the `Basic` challenge (RFC 7617 §2).
    private func challenge() -> ServerResponse {
        var head = HTTPResponse(status: .unauthorized)
        _ = head.headerFields.setValue("Basic realm=\"\(realm)\"", for: .wwwAuthenticate)
        return ServerResponse(head)
    }

    /// Parses `Authorization: Basic base64(user:pass)` (RFC 7617 §2), or nil.
    private static func credential(_ request: HTTPRequest) -> (username: String, password: String)?
    {
        guard let header = request.headerFields[.authorization] else {
            return nil
        }
        let parts = header.split(separator: " ", maxSplits: 1)
        guard parts.count == 2, parts[0].lowercased() == "basic",
            let data = Data(base64Encoded: String(parts[1])),
            let decoded = String(data: data, encoding: .utf8),
            let colon = decoded.firstIndex(of: ":")
        else {
            return nil
        }
        return (String(decoded[..<colon]), String(decoded[decoded.index(after: colon)...]))
    }

    /// Constant-time string equality via double-HMAC under an ephemeral key (length-independent).
    private static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let key = SymmetricKey(size: .bits256)
        let left = HMAC<SHA256>.authenticationCode(for: Data(lhs.utf8), using: key)
        return HMAC<SHA256>
            .isValidAuthenticationCode(
                left, authenticating: Data(rhs.utf8), using: key
            )
    }
}
