//
//  JWTKeyTests.swift
//  HTTPAuthTests
//
//  RFC 7518 §3.2 — "A key of the same size as the hash output (for instance, 256 bits for "HS256") or
//  larger MUST be used with this algorithm." The old `JWT.Key.hs256([UInt8])` case took any length,
//  including empty, so a deployment could sign and "verify" with no secret worth the name (CWE-326).
//  `hs256(secret:)` is the fail-closed constructor; these pin the boundary and the rotation contract on
//  `JWTMiddleware`, which must stay bound to a single `alg` for the RFC 7515 §10.7 confusion defense.
//

import Crypto
import HTTPAuth
import HTTPCore
import HTTPServer
import Testing

@Suite("HTTPAuth — HS256 key length and key rotation (RFC 7518 §3.2)")
struct JWTKeyTests {
    private let header = #"{"alg":"HS256","typ":"JWT"}"#
    private static let retired = Array("retired-jwt-signing-secret-01234".utf8)
    private static let current = Array("current-jwt-signing-secret-01234".utf8)

    @Test(
        "a secret shorter than the SHA-256 digest is refused",
        arguments: [0, 1, 16, 31]
    )
    func refusesShortSecret(length: Int) {
        #expect(JWT.Key.hs256(secret: [UInt8](repeating: 0xAB, count: length)) == nil)
    }

    @Test("exactly 32 octets is accepted — the bound is inclusive")
    func acceptsTheMinimum() {
        #expect(JWT.Key.hs256(secret: [UInt8](repeating: 0xAB, count: 32)) != nil)
    }

    @Test("a token signed with a retired key still verifies while that key is in the set")
    func rotatedKeyStillVerifies() async throws {
        let token = TokenFactory.hs256(
            header: header, payload: #"{"sub":"alice","exp":2000}"#, secret: Self.retired
        )
        let middleware = try #require(
            JWTMiddleware(
                keys: [
                    .hs256(SymmetricKey(data: Self.current)),
                    .hs256(SymmetricKey(data: Self.retired))
                ]
            ) { 1_000 })
        let response = await AuthHarness.run(middleware, authorization: "Bearer " + token)
        #expect(response.head.status.code == 200)
        #expect(response.head.headerFields[.xAuthSubject] == "alice")
    }

    @Test("a token signed with a key outside the set is still 401")
    func unknownKeyIsRejected() async throws {
        let token = TokenFactory.hs256(
            header: header,
            payload: #"{"sub":"alice","exp":2000}"#,
            secret: Array("unknown-jwt-signing-secret-01234".utf8)
        )
        let middleware = try #require(
            JWTMiddleware(keys: [.hs256(SymmetricKey(data: Self.current))]) { 1_000 })
        let response = await AuthHarness.run(middleware, authorization: "Bearer " + token)
        #expect(response.head.status.code == 401)
    }

    @Test("an empty key set is refused — a verifier that trusts nothing must not silently exist")
    func refusesEmptyKeySet() {
        #expect(JWTMiddleware(keys: []) == nil)
    }

    @Test("a key set spanning two algorithms is refused (RFC 7515 §10.7)")
    func refusesMixedAlgorithms() {
        let mixed: [JWT.Key] = [
            .hs256(SymmetricKey(data: Self.current)),
            .es256(P256.Signing.PrivateKey().publicKey)
        ]
        #expect(JWTMiddleware(keys: mixed) == nil)
    }
}
