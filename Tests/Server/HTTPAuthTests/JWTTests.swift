//
//  JWTTests.swift
//  HTTPAuthTests
//
//  RFC 7519 verification matrix against `JWT.verify`: a valid HS256/ES256/RS256 token succeeds; an
//  expired (`exp`), premature (`nbf`), bad-signature, wrong-`aud`, or wrong-`iss` token fails with the
//  matching error. Crucially the algorithm-confusion defenses hold: `alg:"none"` and an HS256 token
//  presented to an ES256 verifier are both rejected as an algorithm mismatch — before any key is touched.
//

// swiftlint:disable sorted_imports - swift-format's OrderedImports sorts `_`-prefixed modules last
import Crypto
import Testing
import _CryptoExtras
// swiftlint:enable sorted_imports

@testable import HTTPAuth

@Suite("HTTPAuth — JWT verification (RFC 7519)")
struct JWTTests {
    let secret: [UInt8] = Array("0123456789abcdef0123456789abcdef".utf8)
    // `nonisolated(unsafe)`: immutable test-fixture keys, read-only across parallel tests. CryptoKit marks
    // these `Sendable` on Darwin, but swift-crypto does not on Linux, so the static-let global needs the
    // explicit opt-out to compile there.
    nonisolated(unsafe) static let ecKey = P256.Signing.PrivateKey()
    nonisolated(unsafe) static let rsaKey = try? _RSA.Signing.PrivateKey(keySize: .bits2048)

    private let hsHeader = #"{"alg":"HS256","typ":"JWT"}"#

    @Test("a valid HS256 token verifies and exposes its claims")
    func validHS256() {
        let token = TokenFactory.hs256(
            header: hsHeader,
            payload: #"{"sub":"alice","exp":2000,"iss":"me","aud":"app"}"#,
            secret: secret
        )
        let result = JWT.verify(
            token,
            key: .hs256(secret),
            audience: "app",
            issuer: "me",
            now: 1_000
        )
        guard case .success(let claims) = result else {
            Issue.record("expected a valid token")
            return
        }
        #expect(claims.subject == "alice")
        #expect(claims.audience == ["app"])
    }

    @Test("a valid ES256 token verifies")
    func validES256() throws {
        let token = try TokenFactory.es256(
            header: #"{"alg":"ES256","typ":"JWT"}"#,
            payload: #"{"sub":"bob","exp":2000}"#,
            key: Self.ecKey
        )
        let result = JWT.verify(token, key: .es256(Self.ecKey.publicKey), now: 1_000)
        guard case .success(let claims) = result else {
            Issue.record("expected a valid ES256 token")
            return
        }
        #expect(claims.subject == "bob")
    }

    @Test("a valid RS256 token verifies")
    func validRS256() throws {
        let key = try #require(Self.rsaKey)
        let token = try TokenFactory.rs256(
            header: #"{"alg":"RS256","typ":"JWT"}"#,
            payload: #"{"sub":"carol","exp":2000}"#,
            key: key
        )
        let result = JWT.verify(token, key: .rs256(key.publicKey), now: 1_000)
        guard case .success(let claims) = result else {
            Issue.record("expected a valid RS256 token")
            return
        }
        #expect(claims.subject == "carol")
    }

    @Test("an expired token is rejected (exp < now)")
    func expired() {
        let token = TokenFactory.hs256(header: hsHeader, payload: #"{"exp":500}"#, secret: secret)
        #expect(JWT.verify(token, key: .hs256(secret), now: 1_000) == .failure(.expired))
    }

    @Test("a not-yet-valid token is rejected (nbf > now)")
    func notYetValid() {
        let token = TokenFactory.hs256(
            header: hsHeader, payload: #"{"nbf":1500,"exp":2000}"#, secret: secret
        )
        #expect(JWT.verify(token, key: .hs256(secret), now: 1_000) == .failure(.notYetValid))
    }

    @Test("a token without exp is rejected by default (unbounded lifetime)")
    func missingExpiration() {
        let token = TokenFactory.hs256(header: hsHeader, payload: #"{"sub":"x"}"#, secret: secret)
        #expect(
            JWT.verify(token, key: .hs256(secret), now: 1_000) == .failure(.missingExpiration))
    }

    @Test("a token without exp is accepted when requireExpiration is disabled")
    func missingExpirationOptOut() {
        let token = TokenFactory.hs256(header: hsHeader, payload: #"{"sub":"x"}"#, secret: secret)
        let result = JWT.verify(
            token, key: .hs256(secret), now: 1_000, requireExpiration: false
        )
        guard case .success(let claims) = result else {
            Issue.record("expected success with requireExpiration disabled")
            return
        }
        #expect(claims.subject == "x")
    }

    @Test("an unrecognized crit JOSE header is rejected (RFC 7515 §4.1.11)")
    func criticalHeader() {
        let token = TokenFactory.hs256(
            header: #"{"alg":"HS256","crit":["b64"],"b64":false}"#,
            payload: #"{"exp":2000}"#,
            secret: secret
        )
        #expect(
            JWT.verify(token, key: .hs256(secret), now: 1_000)
                == .failure(.unsupportedCriticalHeader))
    }

    @Test("a token issued in the future is rejected (iat > now)")
    func issuedInFuture() {
        let token = TokenFactory.hs256(
            header: hsHeader, payload: #"{"iat":1500,"exp":2000}"#, secret: secret
        )
        #expect(JWT.verify(token, key: .hs256(secret), now: 1_000) == .failure(.notYetValid))
    }

    @Test("a non-finite exp is rejected, not treated as eternal")
    func nonFiniteExpiration() {
        let token = TokenFactory.hs256(header: hsHeader, payload: #"{"exp":1e400}"#, secret: secret)
        #expect(JWT.verify(token, key: .hs256(secret), now: 1_000) == .failure(.malformed))
    }

    @Test("a non-strict base64url segment is rejected (JWS malleability)")
    func nonStrictBase64url() {
        // A '+' (standard alphabet) and a '=' (padding) are not valid base64url and must be refused.
        #expect(
            JWT.verify("aa+a.bbbb.cccc", key: .hs256(secret), now: 1_000) == .failure(.malformed))
        #expect(
            JWT.verify("aaaa.bb=b.cccc", key: .hs256(secret), now: 1_000) == .failure(.malformed))
    }

    @Test("a signature under the wrong key is rejected")
    func badSignature() {
        let token = TokenFactory.hs256(
            header: hsHeader,
            payload: #"{"exp":2000}"#,
            secret: Array("the-other-32-byte-long-hmac-key!".utf8)
        )
        #expect(JWT.verify(token, key: .hs256(secret), now: 1_000) == .failure(.badSignature))
    }

    @Test("a wrong audience is rejected")
    func wrongAudience() {
        let token = TokenFactory.hs256(
            header: hsHeader, payload: #"{"aud":"other","exp":2000}"#, secret: secret
        )
        let result = JWT.verify(token, key: .hs256(secret), audience: "app", now: 1_000)
        #expect(result == .failure(.audienceMismatch))
    }

    @Test("a wrong issuer is rejected")
    func wrongIssuer() {
        let token = TokenFactory.hs256(
            header: hsHeader, payload: #"{"iss":"evil","exp":2000}"#, secret: secret
        )
        #expect(
            JWT.verify(token, key: .hs256(secret), issuer: "me", now: 1_000)
                == .failure(.issuerMismatch))
    }

    @Test("alg:\"none\" is rejected before any key is used")
    func algNone() {
        let token = TokenFactory.unsigned(header: #"{"alg":"none"}"#, payload: #"{"exp":2000}"#)
        #expect(JWT.verify(token, key: .hs256(secret), now: 1_000) == .failure(.algorithmMismatch))
    }

    @Test("algorithm confusion: an HS256 token is rejected by an ES256 verifier")
    func algorithmConfusion() {
        let token = TokenFactory.hs256(header: hsHeader, payload: #"{"exp":2000}"#, secret: secret)
        let result = JWT.verify(token, key: .es256(Self.ecKey.publicKey), now: 1_000)
        #expect(result == .failure(.algorithmMismatch))
    }
}
