//
//  TokenFactory.swift
//  HTTPAuthTests
//
//  Signs compact JWS tokens (RFC 7515) for the verification tests — HS256 / ES256 / RS256, plus an
//  unsigned `alg:none` token — reusing the shared, Foundation-free ``Base64`` codec.
//

// swiftlint:disable sorted_imports - swift-format's OrderedImports sorts `_`-prefixed modules last
import Crypto
import Foundation
import HTTPCore
import _CryptoExtras

@testable import HTTPAuth

// swiftlint:enable sorted_imports

/// Builds signed (and deliberately unsigned) JWTs for tests.
enum TokenFactory {
    static func hs256(header: String, payload: String, secret: [UInt8]) -> String {
        let signingInput = segment(header) + "." + segment(payload)
        let mac = HMAC<Crypto.SHA256>
            .authenticationCode(
                for: Data(signingInput.utf8), using: SymmetricKey(data: secret)
            )
        return signingInput + "." + Base64.encode(Array(mac), alphabet: .urlSafe, padded: false)
    }

    static func es256(
        header: String, payload: String, key: P256.Signing.PrivateKey
    ) throws -> String {
        let signingInput = segment(header) + "." + segment(payload)
        let signature = try key.signature(for: Data(signingInput.utf8))
        let raw = Array(signature.rawRepresentation)
        return signingInput + "." + Base64.encode(raw, alphabet: .urlSafe, padded: false)
    }

    static func rs256(
        header: String, payload: String, key: _RSA.Signing.PrivateKey
    ) throws -> String {
        let signingInput = segment(header) + "." + segment(payload)
        let signature = try key.signature(for: Data(signingInput.utf8), padding: .insecurePKCS1v1_5)
        let raw = Array(signature.rawRepresentation)
        return signingInput + "." + Base64.encode(raw, alphabet: .urlSafe, padded: false)
    }

    /// An `alg:none` token with an empty signature segment (the classic forgery attempt).
    static func unsigned(header: String, payload: String) -> String {
        segment(header) + "." + segment(payload) + "."
    }

    private static func segment(_ json: String) -> String {
        Base64.encode(json.utf8, alphabet: .urlSafe, padded: false)
    }
}
