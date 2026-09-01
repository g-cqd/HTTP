//
//  JWTTemporalInputTests.swift
//  HTTPAuthTests
//
//  RFC 7519 §4.1.4 — the `exp`/`nbf`/`iat` checks are ordinary IEEE 754 comparisons, and *every*
//  comparison against a NaN is false. A NaN (or infinite) `now`, or a NaN/infinite/negative `leeway`,
//  therefore makes `now > exp + leeway` false for an expired token and the verifier hands back
//  `.success` — an authentication bypass (CWE-754 improper check for an unusual condition, reached
//  through CWE-20 improper input validation). These tests pin the inputs themselves as untrusted.
//

import Crypto
import Testing

@testable import HTTPAuth

@Suite("HTTPAuth — JWT temporal inputs (RFC 7519 §4.1.4)")
struct JWTTemporalInputTests {
    private let secret: [UInt8] = Array("0123456789abcdef0123456789abcdef".utf8)
    private let header = #"{"alg":"HS256","typ":"JWT"}"#

    private var key: JWT.Key { .hs256(SymmetricKey(data: secret)) }

    /// A token that expired long ago — it must stay rejected under every input below.
    private var expiredToken: String {
        TokenFactory.hs256(header: header, payload: #"{"exp":500}"#, secret: secret)
    }

    /// A token that is valid under any sane clock — it must not slip through on a broken one either.
    private var freshToken: String {
        TokenFactory.hs256(header: header, payload: #"{"exp":2000}"#, secret: secret)
    }

    @Test(
        "a non-finite `now` is refused, not silently compared",
        arguments: [Double.nan, .signalingNaN, .infinity, -.infinity]
    )
    func nonFiniteNow(_ now: Double) {
        #expect(JWT.verify(freshToken, key: key, now: now) == .failure(.invalidClock))
    }

    @Test(
        "an expired token stays expired under a non-finite `now`",
        arguments: [Double.nan, .signalingNaN, .infinity, -.infinity]
    )
    func expiredUnderNonFiniteNow(_ now: Double) {
        let result = JWT.verify(expiredToken, key: key, now: now)
        #expect(!Self.isSuccess(result), "an expired token was accepted with now = \(now)")
        #expect(result == .failure(.invalidClock))
    }

    @Test(
        "a non-finite or negative `leeway` is refused",
        arguments: [Double.nan, .signalingNaN, .infinity, -.infinity, -1, -0.5]
    )
    func invalidLeeway(_ leeway: Double) {
        #expect(
            JWT.verify(freshToken, key: key, now: 1_000, leeway: leeway)
                == .failure(.invalidClock))
    }

    @Test(
        "an expired token stays expired under an invalid `leeway`",
        arguments: [Double.nan, .signalingNaN, .infinity, -.infinity, -1]
    )
    func expiredUnderInvalidLeeway(_ leeway: Double) {
        let result = JWT.verify(expiredToken, key: key, now: 1_000, leeway: leeway)
        #expect(!Self.isSuccess(result), "an expired token was accepted with leeway = \(leeway)")
        #expect(result == .failure(.invalidClock))
    }

    @Test("a finite clock and a non-negative leeway still verify normally")
    func validInputsStillWork() {
        #expect(JWT.verify(expiredToken, key: key, now: 1_000, leeway: 0) == .failure(.expired))
        // 600s of skew tolerance covers the 500s the token has been expired for.
        guard case .success = JWT.verify(expiredToken, key: key, now: 1_000, leeway: 600) else {
            Issue.record("leeway should tolerate the clock skew")
            return
        }
        #expect(Self.isSuccess(JWT.verify(freshToken, key: key, now: 1_000, leeway: 0)))
    }

    @Test("the clock is refused before any signature is verified")
    func refusedBeforeSignatureWork() {
        // A garbage token under a broken clock reports the clock, not the signature: the guard runs
        // first, so a caller cannot spend the verifier's HMAC/RSA budget with an unusable clock.
        #expect(JWT.verify("not.a.token", key: key, now: .nan) == .failure(.invalidClock))
    }

    /// Whether `result` verified — a readable stand-in for an inline `if case .success`.
    private static func isSuccess(_ result: Result<JWT.Claims, JWT.Error>) -> Bool {
        guard case .success = result else {
            return false
        }
        return true
    }
}
