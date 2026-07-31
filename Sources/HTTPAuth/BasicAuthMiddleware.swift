//
//  BasicAuthMiddleware.swift
//  HTTPAuth
//
//  RFC 7617 — HTTP Basic authentication. The `Authorization: Basic base64(user:pass)` credential is
//  verified by an injected closure; a missing or rejected credential gets a `401` with a
//  `WWW-Authenticate: Basic realm="…"` challenge, and the verified username is asserted on `.xAuthSubject`
//  for the handler. Credentials are never logged. The bundled fixed-credential initializer compares in
//  constant time (double-HMAC under a per-instance ephemeral key), so a wrong username and a wrong
//  password are indistinguishable by timing (CWE-208). The blinding key and both expected tags are
//  built once, at init: a request costs two HMACs over the candidate strings, not two 256-bit key
//  generations plus four HMACs.
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
        self.init(realm: realm, verify: Self.fixedCredentialVerifier(username, password))
    }

    /// A constant-time verifier for the one fixed credential `username`/`password`.
    ///
    /// The blinding key and both expected tags are computed here, once per middleware instance, so a
    /// request costs exactly two HMACs over the candidate strings — not two key generations plus four
    /// HMACs. Both comparisons always run: `&&` short-circuits the branch, not the two `let`s above
    /// it, so a wrong username and a wrong password stay timing-indistinguishable (CWE-208).
    static func fixedCredentialVerifier(
        _ username: String,
        _ password: String
    ) -> @Sendable (String, String) -> Bool {
        // A per-instance ephemeral key blinds the comparison: the tags reveal nothing about the
        // credential, and comparing 32-octet tags is length-independent (a direct string compare would
        // leak the credential's length through its running time).
        let key = SymmetricKey(size: .bits256)
        let expectedUser = Self.tag(username, key)
        let expectedPassword = Self.tag(password, key)
        return { candidateUser, candidatePassword in
            let userOK = Self.matches(expectedUser, candidateUser, key)
            let passwordOK = Self.matches(expectedPassword, candidatePassword, key)
            return userOK && passwordOK
        }
    }

    /// The blinded tag of `value` under `key`.
    private static func tag(_ value: String, _ key: SymmetricKey) -> [UInt8] {
        Array(HMAC<Crypto.SHA256>.authenticationCode(for: Data(value.utf8), using: key))
    }

    /// Whether `value` has the precomputed `expected` tag, compared in constant time.
    private static func matches(_ expected: [UInt8], _ value: String, _ key: SymmetricKey) -> Bool {
        HMAC<Crypto.SHA256>
            .isValidAuthenticationCode(
                expected, authenticating: Data(value.utf8), using: key
            )
    }

    /// Verifies the credential, asserts the username for the handler, else challenges with `401`.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        guard let credential = Self.credential(request),
            verify(credential.username, credential.password)
        else {
            return challenge()
        }
        var request = request
        _ = request.headerFields.setValue(credential.username, for: .xAuthSubject)
        return await next.respond(to: request, body: body, context: context)
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
            let data = Base64.decode(parts[1].utf8, alphabet: .standard, padded: true),
            let decoded = String(bytes: data, encoding: .utf8),
            let colon = decoded.firstIndex(of: ":")
        else {
            return nil
        }
        return (String(decoded[..<colon]), String(decoded[decoded.index(after: colon)...]))
    }
}
