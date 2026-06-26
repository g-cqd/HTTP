//
//  Base64URLTests.swift
//  HTTPAuthTests
//
//  RFC 4648 §5 — the unpadded base64url codec round-trips, and malformed input fails closed.
//

import Testing

@testable import HTTPAuth

@Suite("HTTPAuth — base64url (RFC 4648 §5)")
struct Base64URLTests {
    @Test("round-trips arbitrary bytes through encode/decode")
    func roundTrips() {
        let bytes: [UInt8] = [0x00, 0xFF, 0x10, 0x3F, 0xBE, 0xEF, 0x01]
        #expect(Base64URL.decode(Base64URL.encode(bytes)) == bytes)
    }

    @Test("malformed base64url fails closed (nil)")
    func rejectsMalformed() {
        #expect(Base64URL.decode("not valid base64!!") == nil)
    }
}
