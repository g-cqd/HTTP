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
    static let ecKey = P256.Signing.PrivateKey()
    static let rsaKey = try? _RSA.Signing.PrivateKey(keySize: .bits2048)

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
        let token = TokenFactory.hs256(header: hsHeader, payload: #"{"nbf":1500}"#, secret: secret)
        #expect(JWT.verify(token, key: .hs256(secret), now: 1_000) == .failure(.notYetValid))
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
