//
//  Base64Tests.swift
//  HTTPCoreTests
//
//  RFC 4648 — the shared base64 codec: standard (§4, padded) and URL-safe (§5, unpadded) round-trip,
//  decode the canonical vectors, and fail closed on malformed or cross-alphabet input.
//

import Testing

@testable import HTTPCore

@Suite("HTTPCore — base64 (RFC 4648)")
struct Base64Tests {
    @Test("URL-safe unpadded round-trips every length residue", arguments: 0 ... 16)
    func urlSafeRoundTrips(_ length: Int) {
        let bytes = (0 ..< length).map { UInt8(($0 &* 37 &+ 11) & 0xFF) }
        let encoded = Base64.encode(bytes, alphabet: .urlSafe, padded: false)
        #expect(!encoded.contains("="))  // unpadded
        #expect(Base64.decode(encoded, alphabet: .urlSafe, padded: false) == bytes)
    }

    @Test("standard padded round-trips every length residue", arguments: 0 ... 16)
    func standardRoundTrips(_ length: Int) {
        let bytes = (0 ..< length).map { UInt8(($0 &* 53 &+ 7) & 0xFF) }
        let encoded = Base64.encode(bytes, alphabet: .standard, padded: true)
        #expect(encoded.utf8.count % 4 == 0)  // padded to a multiple of 4
        #expect(Base64.decode(encoded, alphabet: .standard, padded: true) == bytes)
    }

    @Test("decodes the canonical `foobar` prefix vectors (RFC 4648 §10)")
    func decodesKnownVectors() {
        // Standard, padded.
        #expect(Base64.decode("Zg==", alphabet: .standard, padded: true) == Array("f".utf8))
        #expect(Base64.decode("Zm8=", alphabet: .standard, padded: true) == Array("fo".utf8))
        #expect(Base64.decode("Zm9v", alphabet: .standard, padded: true) == Array("foo".utf8))
        #expect(
            Base64.decode("Zm9vYmFy", alphabet: .standard, padded: true) == Array("foobar".utf8))
        // URL-safe, unpadded.
        #expect(Base64.decode("Zg", alphabet: .urlSafe, padded: false) == Array("f".utf8))
        #expect(Base64.decode("Zm8", alphabet: .urlSafe, padded: false) == Array("fo".utf8))
        #expect(
            Base64.decode("Zm9vYmFy", alphabet: .urlSafe, padded: false) == Array("foobar".utf8))
    }

    @Test("the two alphabets distinguish `-`/`_` from `+`/`/`")
    func alphabetsAreDistinct() {
        let high: [UInt8] = [0xFB, 0xEF, 0xBE]  // encodes to the sextets 62,62,62,62
        #expect(Base64.encode(high, alphabet: .urlSafe, padded: false) == "----")
        #expect(Base64.encode(high, alphabet: .standard, padded: false) == "++++")
        // A char from the other alphabet is rejected.
        #expect(Base64.decode("++++", alphabet: .urlSafe, padded: false) == nil)
        #expect(Base64.decode("----", alphabet: .standard, padded: true) == nil)
    }

    @Test("rejects malformed shapes")
    func rejectsMalformed() {
        #expect(Base64.decode("Z", alphabet: .urlSafe, padded: false) == nil)  // ≡1 (mod 4)
        #expect(Base64.decode("not base64!!", alphabet: .urlSafe, padded: false) == nil)
        #expect(Base64.decode("Zg=", alphabet: .standard, padded: true) == nil)  // not %4==0
        #expect(Base64.decode("Zg==", alphabet: .urlSafe, padded: false) == nil)  // '=' unpadded
        #expect(Base64.decode("Z=g=", alphabet: .standard, padded: true) == nil)  // data after =
    }

    @Test("rejects a non-minimal (non-zero trailing-bit) encoding (RFC 4648 §3.5)")
    func rejectsNonCanonical() {
        #expect(Base64.decode("Zw", alphabet: .urlSafe, padded: false) == [0x67])  // canonical
        #expect(Base64.decode("Zh", alphabet: .urlSafe, padded: false) == nil)  // non-zero pad bits
    }
}
