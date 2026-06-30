//
//  CryptoPrimitivesTests.swift
//  HTTPCoreTests
//
//  Known-answer vectors for the pure-Swift crypto primitives, independent of any crypto library:
//  FIPS 180-4 for SHA-256, RFC 4231 for HMAC-SHA256, and RFC 5869 Appendix A for HKDF. These lock in
//  byte-correctness (a measured decision kept these pure-Swift rather than pulling swift-crypto/BoringSSL
//  into the dependency-light core — same output, smaller attack surface). The constant-time comparison
//  and HKDF's range guard are exercised too.
//

import Testing

@testable import HTTPCore

@Suite("Pure-Swift crypto — known-answer vectors (FIPS 180-4 / RFC 4231 / RFC 5869)")
struct CryptoPrimitivesTests {
    @Test("SHA-256 matches the FIPS 180-4 vectors")
    func sha256() {
        #expect(
            hex(SHA256.hash(Array("abc".utf8)))
                == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(
            hex(SHA256.hash([]))
                == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test("HMAC-SHA256 matches the RFC 4231 vectors")
    func hmac() {
        let key1 = [UInt8](repeating: 0x0B, count: 20)
        let case1 = HMACSHA256.authenticationCode(key: key1, message: Array("Hi There".utf8))
        #expect(
            hex(case1) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        let msg2 = Array("what do ya want for nothing?".utf8)
        let case2 = HMACSHA256.authenticationCode(key: Array("Jefe".utf8), message: msg2)
        #expect(
            hex(case2) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    }

    @Test("constant-time comparison distinguishes equal, differing, and length-mismatched inputs")
    func constantTimeEquals() {
        #expect(HMACSHA256.constantTimeEquals([1, 2, 3], [1, 2, 3]))
        #expect(!HMACSHA256.constantTimeEquals([1, 2, 3], [1, 2, 4]))
        #expect(!HMACSHA256.constantTimeEquals([1, 2, 3], [1, 2]))
    }

    @Test("HKDF-SHA256 matches the RFC 5869 Appendix A.1 vector")
    func hkdf() {
        let ikm = [UInt8](repeating: 0x0B, count: 22)
        let salt = bytes("000102030405060708090a0b0c")
        let info = bytes("f0f1f2f3f4f5f6f7f8f9")
        let prk = HKDF.extract(salt: salt, inputKeyMaterial: ikm)
        #expect(
            hex(prk) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        let okm = HKDF.derive(inputKeyMaterial: ikm, salt: salt, info: info, length: 42)
        let expectedOKM =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        #expect(okm.map(hex) == expectedOKM)
    }

    @Test("HKDF rejects an out-of-range length, never trapping")
    func hkdfRejectsLength() {
        let prk = [UInt8](repeating: 0x01, count: 32)
        #expect(HKDF.expand(pseudoRandomKey: prk, length: 255 * 32 + 1) == nil)
        #expect(HKDF.expand(pseudoRandomKey: prk, length: 0)?.isEmpty == true)
    }

    /// Lowercase hex, no separators — Foundation-free, matching the core's no-Foundation posture.
    private func hex(_ raw: [UInt8]) -> String {
        raw.map { ($0 < 16 ? "0" : "") + String($0, radix: 16) }.joined()
    }

    /// Decodes a lowercase hex string into bytes (even length assumed; test fixtures only).
    private func bytes(_ string: String) -> [UInt8] {
        var result: [UInt8] = []
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            result.append(UInt8(string[index ..< next], radix: 16) ?? 0)
            index = next
        }
        return result
    }
}
