//
//  RandomTokenTests.swift
//  HTTPCoreTests
//
//  CWE-1288 (improper validation of an unsafe equivalence in input) — an identifier rendering must be
//  injective. These pin the fixed 32-lowercase-hex-digit width and, crucially, the exact pair that
//  collides under the `String(high, radix: 16) + String(low, radix: 16)` rendering the session and
//  request-id middleware used to share: `(0x1, 0x23)` and `(0x12, 0x3)` both rendered "123", so one
//  session id could be presented as another. A scripted generator injects those words directly.
//

import Testing

@testable import HTTPCore

@Suite("RandomToken — fixed-width, injective 128-bit hex identifiers (CWE-1288)")
struct RandomTokenTests {
    /// A `RandomNumberGenerator` yielding scripted 64-bit words.
    ///
    /// Lets a test pin the rendering of chosen values. Yields 0 once the script is exhausted;
    /// test-only, never a source of real entropy.
    private struct ScriptedGenerator: RandomNumberGenerator {
        private let words: [UInt64]
        private var index = 0

        init(_ words: [UInt64]) {
            self.words = words
        }

        mutating func next() -> UInt64 {
            defer { index += 1 }
            return index < words.count ? words[index] : 0
        }
    }

    @Test("a system-generated token is exactly 32 lowercase hex digits")
    func systemTokenShape() {
        let token = RandomToken.hex128()
        #expect(token.count == 32)
        #expect(
            token.utf8.allSatisfy {
                (0x30 ... 0x39).contains($0) || (0x61 ... 0x66).contains($0)
            })
    }

    @Test(
        "each 128-bit value renders to its own 32 zero-padded digits",
        arguments: [
            (high: UInt64(0x1), low: UInt64(0x23), hex: "00000000000000010000000000000023"),
            (high: UInt64(0x12), low: UInt64(0x3), hex: "00000000000000120000000000000003"),
            (high: UInt64.min, low: UInt64.min, hex: String(repeating: "0", count: 32)),
            (high: UInt64.max, low: UInt64.max, hex: String(repeating: "f", count: 32)),
            (
                high: UInt64(0xDEAD_BEEF_0000_0000), low: UInt64(0x0123_4567_89AB_CDEF),
                hex: "deadbeef000000000123456789abcdef"
            )
        ]
    )
    func renders(vector: (high: UInt64, low: UInt64, hex: String)) {
        var generator = ScriptedGenerator([vector.high, vector.low])
        #expect(RandomToken.hex128(using: &generator) == vector.hex)
    }

    @Test("the pair that collides under unpadded radix-16 concatenation renders distinctly")
    func injectiveOnTheCollidingPair() {
        var first = ScriptedGenerator([0x1, 0x23])
        var second = ScriptedGenerator([0x12, 0x3])
        // `String(0x1, radix: 16) + String(0x23, radix: 16)` and `String(0x12, …) + String(0x3, …)` are
        // both "123": two distinct 128-bit values, one identifier.
        #expect(RandomToken.hex128(using: &first) != RandomToken.hex128(using: &second))
    }
}
