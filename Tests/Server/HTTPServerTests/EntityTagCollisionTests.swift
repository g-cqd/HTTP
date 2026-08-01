//
//  EntityTagCollisionTests.swift
//  HTTPServerTests
//
//  REG-4b — the middleware entity-tag must not claim to be a *strong* validator.
//
//  RFC 9110 §8.8.1 defines a strong validator as one that "changes value whenever a change occurs to
//  the representation data that would be observable in the content", and suggests "a collision-resistant
//  hash of the representation data". CRC-32 (RFC 1952 §8) is a 32-bit error-detecting code, not a hash:
//  it is affine over GF(2), so a same-length collision is *constructed*, not hoped for.
//
//  The pair below is that construction. Both bodies are 33 octets and both check to 0xef17e7dc, so the
//  size-plus-CRC-32 tag is byte-identical for a body that says `"role":"user"` and one that says
//  `"role":"admin"` — found by a birthday search over an 8-octet padding field, which for a 32-bit code
//  costs a fraction of a second (CWE-328, use of a weak hash; CWE-354, missing integrity check).
//
//  What that breaks if the tag is strong: `If-Match` (§13.1.1) would authorize an update against a
//  representation the client never saw, and `If-Range` (§13.1.5) would let a client splice a range out
//  of the *other* body into its cached copy. Both use the STRONG comparison function, which is exactly
//  the promise CRC-32 cannot keep, so the tag is now weak (`W/`) and neither can be satisfied.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Entity tags — CRC-32 is not a strong validator (RFC 9110 §8.8.1, REG-4b)")
struct EntityTagCollisionTests {
    /// A 33-octet body a client is authorized to read.
    private static let userBody = Array(#"{"role":"user" ,"pad":"aaaalzmt"}"#.utf8)

    /// A different 33-octet body with the identical CRC-32 — the collision.
    private static let adminBody = Array(#"{"role":"admin","pad":"aarraaaa"}"#.utf8)

    @Test("the two bodies are a same-length CRC-32 collision (the construction is the proof)")
    func collisionHolds() {
        #expect(Self.userBody != Self.adminBody)
        #expect(Self.userBody.count == Self.adminBody.count)
        #expect(CRC32.checksum(Self.userBody) == CRC32.checksum(Self.adminBody))
        // Therefore the size-plus-CRC-32 tag cannot tell them apart at all.
        #expect(EntityTag.crc(for: Self.userBody) == EntityTag.crc(for: Self.adminBody))
    }

    @Test("the middleware tag is weak, so it is never a strong validator (RFC 9110 §8.8.3)")
    func tagIsWeak() {
        #expect(EntityTag.crc(for: Self.userBody).hasPrefix("W/"))
    }

    @Test("a colliding tag cannot satisfy If-Match (RFC 9110 §13.1.1)")
    func collidingTagFailsIfMatch() async {
        // The client holds the tag it was given for `userBody`; the representation is now `adminBody`.
        let tag = EntityTag.crc(for: Self.userBody)
        let response = await Self.responder(Self.adminBody)
            .respond(to: Self.get(ifMatch: tag), body: [])
        #expect(response.head.status == .preconditionFailed)
        #expect(response.body.isEmpty)
    }

    @Test("a colliding tag cannot satisfy If-Range, so no range is spliced (RFC 9110 §13.1.5)")
    func collidingTagFailsIfRange() async {
        let tag = EntityTag.crc(for: Self.userBody)
        let response = await Self.rangeResponder(Self.adminBody)
            .respond(to: Self.get(range: "bytes=0-3", ifRange: tag), body: [])
        // If-Range unsatisfied → the whole representation, never a 206 carved from the other body.
        #expect(response.head.status == .ok)
        #expect(response.body == Self.adminBody)
    }

    @Test("a weak tag still serves If-None-Match / 304 — the half weak comparison covers (§13.1.2)")
    func weakTagStillRevalidates() async {
        let tag = EntityTag.crc(for: Self.adminBody)
        let response = await Self.responder(Self.adminBody)
            .respond(to: Self.get(ifNoneMatch: tag), body: [])
        #expect(response.head.status == .notModified)
    }

    private static func responder(_ body: [UInt8]) -> any HTTPResponder {
        ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok), body: body) }
            .wrapped(by: ConditionalRequestMiddleware())
    }

    private static func rangeResponder(_ body: [UInt8]) -> any HTTPResponder {
        ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok), body: body) }
            .wrapped(by: RangeMiddleware())
    }

    private static func get(
        ifMatch: String? = nil,
        ifNoneMatch: String? = nil,
        range: String? = nil,
        ifRange: String? = nil
    ) -> HTTPRequest {
        var fields = HTTPFields()
        if let ifMatch { _ = fields.append(ifMatch, for: .ifMatch) }
        if let ifNoneMatch { _ = fields.append(ifNoneMatch, for: .ifNoneMatch) }
        if let range { _ = fields.append(range, for: .range) }
        if let ifRange { _ = fields.append(ifRange, for: .ifRange) }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }
}
