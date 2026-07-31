//
//  SessionSigningKeysTests.swift
//  HTTPServerTests
//
//  The two properties the key set exists for. (1) Fail-closed length: NIST SP 800-107r1 §5.3.4 requires
//  HMAC key material at least as long as the digest, so anything under 32 octets — including the empty
//  key the previous `init(key: [UInt8], …)` accepted without a word — is refused (CWE-326). (2)
//  Rotation: a cookie signed under a key that has since been retired into `previous` still verifies, so
//  a key roll does not log every user out; a cookie signed under a key the set has never seen is
//  rejected, so `previous` is not a blanket "accept anything".
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("SessionSigningKeys — key-length contract and rotation (NIST SP 800-107r1 §5.3.4)")
struct SessionSigningKeysTests {
    private static let keyA = Array("session-signing-key-A-0123456789".utf8)
    private static let keyB = Array("session-signing-key-B-0123456789".utf8)
    private static let unknown = Array("session-signing-key-X-0123456789".utf8)

    private let echo = ClosureResponder { request, _, _ in
        ServerResponse(HTTPResponse(status: .ok, headerFields: request.headerFields))
    }

    @Test("a key shorter than the SHA-256 digest is refused", arguments: [0, 1, 16, 31])
    func refusesShortCurrentKey(length: Int) {
        #expect(SessionSigningKeys(current: [UInt8](repeating: 0xAB, count: length)) == nil)
    }

    @Test(
        "a short retired key is refused too — rotation is not an escape hatch",
        arguments: [0, 16, 31])
    func refusesShortPreviousKey(length: Int) {
        let keys = SessionSigningKeys(
            current: Self.keyA,
            previous: [[UInt8](repeating: 0xAB, count: length)]
        )
        #expect(keys == nil)
    }

    @Test("exactly 32 octets is accepted — the bound is inclusive")
    func acceptsTheMinimum() {
        #expect(SessionSigningKeys.minimumKeyLength == 32)
        #expect(SessionSigningKeys(current: [UInt8](repeating: 0xAB, count: 32)) != nil)
    }

    @Test("a cookie signed with a rotated-out key still verifies while it is in `previous`")
    func rotatedKeyStillVerifies() async throws {
        let issued = try await issueCookie(signedWith: Self.keyB)
        // keyB has been retired: keyA now signs, keyB still verifies.
        let rotated = try #require(SessionSigningKeys(current: Self.keyA, previous: [Self.keyB]))
        let response = await respond(cookie: issued, keys: rotated)
        #expect(response.head.headerFields[.setCookie] == nil)  // accepted, so no re-issue
        #expect(response.head.headerFields[.xSessionID] == "sid-rotated")
    }

    @Test("a cookie signed with an unknown key is rejected and a fresh session is issued")
    func unknownKeyIsRejected() async throws {
        let issued = try await issueCookie(signedWith: Self.unknown)
        let known = try #require(SessionSigningKeys(current: Self.keyA, previous: [Self.keyB]))
        let response = await respond(cookie: issued, keys: known)
        #expect(response.head.headerFields[.setCookie]?.hasPrefix("session=fresh.") == true)
        #expect(response.head.headerFields[.xSessionID] == "fresh")  // never "sid-rotated"
    }

    /// The bare `session=<id>.<tag>` pair a middleware signing with `key` issues for `sid-rotated`.
    private func issueCookie(signedWith key: [UInt8]) async throws -> String {
        let keys = try #require(SessionSigningKeys(current: key))
        let middleware = SessionMiddleware(keys: keys, isSecure: false) { "sid-rotated" }
        let response = await middleware.respond(to: request(), body: [], next: echo)
        return String((response.head.headerFields[.setCookie] ?? "").prefix { $0 != ";" })
    }

    /// Presents `cookie` to a middleware verifying with `keys`, minting `fresh` if it is not accepted.
    private func respond(cookie: String, keys: SessionSigningKeys) async -> ServerResponse {
        let middleware = SessionMiddleware(keys: keys, isSecure: false) { "fresh" }
        return await middleware.respond(to: request(cookie: cookie), body: [], next: echo)
    }

    private func request(cookie: String? = nil) -> HTTPRequest {
        var fields = HTTPFields()
        if let cookie { _ = fields.append(cookie, for: .cookie) }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }
}
