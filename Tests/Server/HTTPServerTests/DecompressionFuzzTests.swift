//
//  DecompressionFuzzTests.swift
//  HTTPServerTests
//
//  Deterministic fuzzing for the inbound gzip decoder (RFC 1952 / CWE-409) — fuzz parity with the
//  protocol decoders. It reads an untrusted, attacker-controlled body and slices a gzip envelope before
//  decoding, so it must NEVER trap (the 10-octet header / 8-octet trailer arithmetic and the buffer
//  sizing are the overflow-prone spots) and only ever returns a capped body or nil. Random bytes and a
//  mutated valid gzip member exercise both the envelope check and the DEFLATE decode.
//

import HTTPTestSupport
import Testing

@testable import HTTPServer

private func fuzzInflate(_ bytes: [UInt8]) {
    _ = Inflate.gunzip(bytes, maxOutput: 64 * 1_024)
}

@Suite("Fuzzing — the gzip decoder never traps (RFC 1952 / CWE-409)", .tags(.fuzz))
struct DecompressionFuzzTests {
    private let iterations = 4_000

    @Test
    func `gunzip tolerates arbitrary random bytes`() {
        var rng = SeededRNG(named: "inflate.random")
        for _ in 0 ..< iterations {
            let length = rng.below(256)
            var bytes: [UInt8] = []
            bytes.reserveCapacity(length)
            for _ in 0 ..< length {
                bytes.append(rng.byte())
            }
            fuzzInflate(bytes)
        }
    }

    @Test
    func `gunzip tolerates a mutated valid gzip member`() {
        let report = fuzzNeverTraps(
            seed: .named("inflate.mutated"),
            iterations: iterations,
            corpus: { Gzip.compress(Array("the quick brown fox. ".utf8)) ?? [] },
            exercise: fuzzInflate
        )
        #expect(report.iterations == iterations)
    }
}
