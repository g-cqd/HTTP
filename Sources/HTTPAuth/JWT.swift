//
//  JWT.swift
//  HTTPAuth
//
//  RFC 7519 / RFC 7515 — compact JWS verification (`header.payload.signature`). A verifier is bound to ONE
//  algorithm + key, so it rejects a token whose header `alg` differs — the algorithm-confusion attack,
//  e.g. an HS256 token forged with an RSA public key as the HMAC secret — and rejects `alg:"none"`
//  outright. Only after the signature checks out are the registered claims validated: `exp`/`nbf` (with a
//  configurable `leeway`) and the optional `aud`/`iss`. Signatures use swift-crypto: HS256 = HMAC-SHA256,
//  ES256 = P-256 ECDSA (SHA-256), RS256 = RSA PKCS#1 v1.5 (SHA-256).
//

// swiftlint:disable sorted_imports - swift-format's OrderedImports sorts `_`-prefixed modules last
public import Crypto
internal import Foundation
internal import HTTPCore
public import _CryptoExtras

// swiftlint:enable sorted_imports

/// Verifies compact JWS tokens (RFC 7519) against a single bound key/algorithm.
public enum JWT {
    /// Why a token failed verification.
    public enum Error: Swift.Error, Equatable, Sendable {
        case malformed
        case algorithmMismatch
        case badSignature
        /// The JOSE header carried a `crit` parameter this verifier does not understand (RFC 7515 §4.1.11).
        case unsupportedCriticalHeader
        case expired
        /// `exp` was absent and `requireExpiration` (the default) demands a bounded lifetime.
        case missingExpiration
        case notYetValid
        case audienceMismatch
        case issuerMismatch
    }

    /// A verification key bound to one JWS algorithm (RFC 7518); the binding is the confusion defense.
    ///
    /// `@unchecked Sendable`: the payloads are immutable public keys. CryptoKit marks
    /// `P256.Signing.PublicKey` `Sendable` on Darwin, but swift-crypto does not on Linux, so a checked
    /// conformance fails to compile there; the keys carry no mutable state, so the unchecked conformance is
    /// sound on both platforms.
    public enum Key: @unchecked Sendable {
        case hs256([UInt8])  // shared secret
        case es256(P256.Signing.PublicKey)
        case rs256(_RSA.Signing.PublicKey)

        /// The `alg` header value this key verifies.
        var algorithm: String {
            switch self {
                case .hs256:
                    return "HS256"
                case .es256:
                    return "ES256"
                case .rs256:
                    return "RS256"
            }
        }
    }

    /// The registered claims a verified token carries (RFC 7519 §4.1).
    public struct Claims: Sendable, Equatable {
        /// The `sub` claim — the verified principal.
        public let subject: String?
        /// The `iss` claim — the token's issuer.
        public let issuer: String?
        /// The `aud` claim — the audiences the token is for.
        public let audience: [String]
        /// The `exp` claim — expiry, in epoch seconds.
        public let expiration: Double?
        /// The `nbf` claim — not-valid-before, in epoch seconds.
        public let notBefore: Double?
        /// The `iat` claim — issued-at, in epoch seconds.
        public let issuedAt: Double?
    }

    /// Verifies `token` against `key`, validating the claims at `now` (epoch seconds) and returning the
    /// claims or the first failure.
    ///
    /// Rejects `alg:"none"`, an `alg` that differs from `key` (algorithm confusion), and any unrecognized
    /// `crit` JOSE header (RFC 7515 §4.1.11). Validates `exp`/`nbf`/`iat` (± `leeway`) and the optional
    /// `audience`/`issuer`; non-finite numeric claims are rejected. By default a token MUST carry `exp`
    /// (`requireExpiration`) so an unbounded-lifetime token is not silently accepted.
    public static func verify(
        _ token: some StringProtocol,
        key: Key,
        audience: String? = nil,
        issuer: String? = nil,
        now: Double,
        leeway: Double = 0,
        requireExpiration: Bool = true
    ) -> Result<Claims, Error> {
        guard let parsed = parse(token) else {
            return .failure(.malformed)
        }
        guard !parsed.hasCriticalHeader else {
            return .failure(.unsupportedCriticalHeader)
        }
        guard parsed.algorithm != "none", parsed.algorithm == key.algorithm else {
            return .failure(.algorithmMismatch)
        }
        guard verifySignature(parsed.signature, over: parsed.signingInput, key: key) else {
            return .failure(.badSignature)
        }
        guard let claims = decodeClaims(parsed.payload) else {
            return .failure(.malformed)
        }
        let failure = validate(
            claims,
            audience: audience,
            issuer: issuer,
            now: now,
            leeway: leeway,
            requireExpiration: requireExpiration
        )
        if let failure {
            return .failure(failure)
        }
        return .success(claims)
    }

    /// The decoded pieces of a compact JWS, or nil if it is not three valid base64url segments.
    private static func parse(_ token: some StringProtocol) -> ParsedToken? {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else {
            return nil
        }
        // Decode straight from each segment's `UTF8View` — no `String(segments[i])` materialization. The
        // signing input is sliced from `token` below, so the segments are only ever fed to the decoder.
        guard let headerBytes = Base64.decode(segments[0].utf8, alphabet: .urlSafe, padded: false),
            let payloadBytes = Base64.decode(segments[1].utf8, alphabet: .urlSafe, padded: false),
            let signature = Base64.decode(segments[2].utf8, alphabet: .urlSafe, padded: false),
            let jose = decodeHeader(headerBytes)
        else {
            return nil
        }
        // The JWS signing input is `header.payload` — the token up to (but excluding) the second '.', i.e.
        // where the payload segment ends. Slice those bytes from `token` directly (no rebuilt `String`).
        return ParsedToken(
            algorithm: jose.alg,
            hasCriticalHeader: jose.crit != nil,
            payload: payloadBytes,
            signature: signature,
            signingInput: Array(token[..<segments[1].endIndex].utf8)
        )
    }

    /// Verifies the signature for the bound algorithm in constant time (HMAC) / via swift-crypto (EC/RSA).
    private static func verifySignature(
        _ signature: [UInt8],
        over signingInput: [UInt8],
        key: Key
    ) -> Bool {
        // `[UInt8]` conforms to `DataProtocol`/`ContiguousBytes`, so the signature and signing input go
        // straight into swift-crypto — no per-verify `Data(...)` copy of either buffer.
        switch key {
            case .hs256(let secret):
                return HMAC<Crypto.SHA256>
                    .isValidAuthenticationCode(
                        signature,
                        authenticating: signingInput,
                        using: SymmetricKey(data: secret)
                    )
            case .es256(let publicKey):
                guard let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
                else {
                    return false
                }
                return publicKey.isValidSignature(parsed, for: signingInput)
            case .rs256(let publicKey):
                let parsed = _RSA.Signing.RSASignature(rawRepresentation: signature)
                return publicKey.isValidSignature(
                    parsed, for: signingInput, padding: .insecurePKCS1v1_5
                )
        }
    }

    /// The decoded JOSE header (`alg` plus any `crit`), or nil if it is not a decodable header (§4.1.1).
    private static func decodeHeader(_ bytes: [UInt8]) -> JOSEHeader? {
        try? JSONDecoder().decode(JOSEHeader.self, from: Data(bytes))
    }

    /// The registered claims from the payload, or nil if it is not a decodable claims object.
    private static func decodeClaims(_ bytes: [UInt8]) -> Claims? {
        guard let payload = try? JSONDecoder().decode(ClaimsPayload.self, from: Data(bytes)) else {
            return nil
        }
        return Claims(
            subject: payload.sub,
            issuer: payload.iss,
            audience: payload.aud?.values ?? [],
            expiration: payload.exp,
            notBefore: payload.nbf,
            issuedAt: payload.iat
        )
    }

    /// The first claim that fails for the given constraints, or nil if all pass (RFC 7519 §4.1).
    private static func validate(
        _ claims: Claims,
        audience: String?,
        issuer: String?,
        now: Double,
        leeway: Double,
        requireExpiration: Bool
    ) -> Error? {
        // Reject non-finite numeric claims: a JSON `exp: 1e400` decodes to `+Inf` and would never expire.
        for value in [claims.expiration, claims.notBefore, claims.issuedAt] {
            if let value, !value.isFinite {
                return .malformed
            }
        }
        guard claims.expiration != nil || !requireExpiration else {
            return .missingExpiration  // an unbounded-lifetime token is not accepted by default
        }
        if let expiration = claims.expiration, now > expiration + leeway {
            return .expired
        }
        if let notBefore = claims.notBefore, now + leeway < notBefore {
            return .notYetValid
        }
        if let issuedAt = claims.issuedAt, issuedAt > now + leeway {
            return .notYetValid  // issued in the future beyond the allowed clock skew
        }
        if let audience, !claims.audience.contains(audience) {
            return .audienceMismatch
        }
        if let issuer, claims.issuer != issuer {
            return .issuerMismatch
        }
        return nil
    }

    /// The decoded pieces of a compact JWS the verifier works over.
    private struct ParsedToken {
        let algorithm: String
        let hasCriticalHeader: Bool
        let payload: [UInt8]
        let signature: [UInt8]
        let signingInput: [UInt8]
    }

    /// The JOSE header — `alg` is consulted; a present `crit` (§4.1.11) makes the token unverifiable here.
    private struct JOSEHeader: Decodable {
        let alg: String
        let crit: [String]?
    }

    /// The registered claims as decoded from the payload (RFC 7519 §4.1).
    private struct ClaimsPayload: Decodable {
        let sub: String?
        let iss: String?
        let aud: Audience?
        let exp: Double?
        let nbf: Double?
        let iat: Double?
    }

    /// `aud` is either a single string or an array of strings (RFC 7519 §4.1.3).
    private enum Audience: Decodable {
        case single(String)
        case multiple([String])

        init(from decoder: any Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let one = try? container.decode(String.self) {
                self = .single(one)
            }
            else {
                self = .multiple(try container.decode([String].self))
            }
        }

        var values: [String] {
            switch self {
                case .single(let value):
                    return [value]
                case .multiple(let values):
                    return values
            }
        }
    }
}
