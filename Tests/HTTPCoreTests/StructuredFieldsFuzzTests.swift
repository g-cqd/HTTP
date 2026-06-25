//
//  StructuredFieldsFuzzTests.swift
//  HTTPCoreTests
//
//  Deterministic fuzzing for the RFC 8941 Structured Fields parser — fuzz parity with the HTTP/1,
//  HTTP/2, HTTP/3, HPACK, QPACK, and WebSocket decoders. The parser reads untrusted header values, so
//  it must NEVER trap, hang, or exhaust memory: it may only return a value or throw a typed
//  `StructuredFields.ParseError`. Reaching the end of a run (the process did not crash) is the
//  assertion; a fixed seed keeps any failure reproducible. The RNG + byte mutator come from
//  `HTTPTestSupport`.
//

import HTTPCore
import HTTPTestSupport
import Testing

private func fuzzItem(_ bytes: [UInt8]) {
    _ = try? StructuredFields.parseItem(String(decoding: bytes, as: Unicode.UTF8.self))
}

private func fuzzList(_ bytes: [UInt8]) {
    _ = try? StructuredFields.parseList(String(decoding: bytes, as: Unicode.UTF8.self))
}

private func fuzzDictionary(_ bytes: [UInt8]) {
    _ = try? StructuredFields.parseDictionary(String(decoding: bytes, as: Unicode.UTF8.self))
}

@Suite("Fuzzing — RFC 8941 Structured Fields parser never traps", .tags(.fuzz))
struct StructuredFieldsFuzzTests {
    private let iterations = 4_000

    @Test
    func `all three parsers tolerate arbitrary random bytes`() {
        var rng = SeededRNG(named: "sf.random")
        for _ in 0 ..< iterations {
            let length = rng.below(257)
            var bytes: [UInt8] = []
            bytes.reserveCapacity(length)
            for _ in 0 ..< length {
                bytes.append(rng.byte())
            }
            fuzzItem(bytes)
            fuzzList(bytes)
            fuzzDictionary(bytes)
        }
    }

    @Test
    func `parseItem tolerates mutated valid items`() {
        let report = fuzzNeverTraps(
            seed: .named("sf.item.mutated"),
            iterations: iterations,
            corpus: { Array("42;foo=bar;n=?0".utf8) },
            exercise: fuzzItem
        )
        #expect(report.iterations == iterations)
    }

    @Test
    func `parseList tolerates mutated valid lists`() {
        let report = fuzzNeverTraps(
            seed: .named("sf.list.mutated"),
            iterations: iterations,
            corpus: { Array("a, b;p=1, (c d);q=1, :aGVsbG8=:".utf8) },
            exercise: fuzzList
        )
        #expect(report.iterations == iterations)
    }

    @Test
    func `parseDictionary tolerates mutated valid dictionaries`() {
        let report = fuzzNeverTraps(
            seed: .named("sf.dict.mutated"),
            iterations: iterations,
            corpus: { Array("a=1, b=?0, c=(x y), d=\"s\";q=1".utf8) },
            exercise: fuzzDictionary
        )
        #expect(report.iterations == iterations)
    }
}
