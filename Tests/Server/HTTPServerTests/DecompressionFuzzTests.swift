//
//  DecompressionFuzzTests.swift
//  HTTPServerTests
//
//  Deterministic fuzzing for the inbound decoders — gzip, deflate, and Brotli (RFC 1952 / 1951 / 7932,
//  CWE-409). Each reads an untrusted, attacker-controlled body and parses an envelope before decoding,
//  so it must NEVER trap (the gzip header/trailer + FLG-field arithmetic and the buffer sizing are the
//  overflow-prone spots) and only ever returns a capped body or nil. Random bytes and a mutated valid
//  gzip member exercise the envelope parsing and the DEFLATE/Brotli decode on every path.
//

import HTTPTestSupport
import Testing

@testable import HTTPServer

private func fuzzInflate(_ bytes: [UInt8]) {
    _ = Inflate.gunzip(bytes, maxOutput: 64 * 1_024)
    _ = Inflate.decompress(bytes, encoding: "deflate", maxOutput: 64 * 1_024)
    _ = Inflate.decompress(bytes, encoding: "br", maxOutput: 64 * 1_024)
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
