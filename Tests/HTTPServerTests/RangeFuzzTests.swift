//
//  RangeFuzzTests.swift
//  HTTPServerTests
//
//  Deterministic fuzzing for the `Range` header parser (RFC 9110 §14.1.2) — fuzz parity with the
//  protocol decoders. It reads an untrusted header value and computes byte offsets, so it must NEVER
//  trap (the suffix subtraction and `Int(...)` digit parsing are the overflow-prone spots): it may only
//  return one of the three `ParsedRange` outcomes. The body total is varied across its edge values
//  (0, 1, large, `Int.max`) each iteration so the clamp/`unsatisfiable` arithmetic is exercised too.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTPServer

private func fuzzRange(_ bytes: [UInt8]) {
    let value = String(decoding: bytes, as: Unicode.UTF8.self)
    for total in [0, 1, 1_000, Int.max] {
        _ = RangeMiddleware.parse(value, total: total)
    }
}

@Suite("Fuzzing — the Range parser never traps (RFC 9110 §14.1)", .tags(.fuzz))
struct RangeFuzzTests {
    private let iterations = 4_000

    @Test
    func `parse tolerates arbitrary random bytes`() {
        var rng = SeededRNG(named: "range.random")
        for _ in 0 ..< iterations {
            let length = rng.below(64)
            var bytes: [UInt8] = []
            bytes.reserveCapacity(length)
            for _ in 0 ..< length {
                bytes.append(rng.byte())
            }
            fuzzRange(bytes)
        }
    }

    @Test
    func `parse tolerates mutated valid byte ranges`() {
        let report = fuzzNeverTraps(
            seed: .named("range.mutated"),
            iterations: iterations,
            corpus: { Array("bytes=100-499".utf8) },
            exercise: fuzzRange
        )
        #expect(report.iterations == iterations)
    }
}
