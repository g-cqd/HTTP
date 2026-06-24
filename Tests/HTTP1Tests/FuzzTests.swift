//
//  FuzzTests.swift
//  HTTP1Tests
//
//  Deterministic fuzzing: feed random and mutated bytes to every HTTP/1.1 parser and assert they
//  NEVER trap — they may only return a value or throw a typed `HTTP1ParseError`. Reaching the end of
//  each run (the process did not crash) is the assertion. A fixed seed keeps failures reproducible.
//  The seeded RNG and the byte mutator come from `HTTPTestSupport` (no hand-rolled copies here).
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP1

private func parseRequest(_ bytes: [UInt8]) {
    bytes.withUnsafeBytes { raw in
        var reader = ByteReader(raw)
        _ = try? RequestParser.parse(&reader, limits: .default)
    }
}

private func decodeChunked(_ bytes: [UInt8]) {
    bytes.withUnsafeBytes { raw in
        var reader = ByteReader(raw)
        _ = try? ChunkedDecoder.decode(&reader, limits: .default)
    }
}

@Suite("Fuzzing — parsers never trap, only return or throw", .tags(.fuzz))
struct FuzzTests {
    private let iterations = 4_000

    @Test
    func `RequestParser tolerates arbitrary random bytes`() {
        var rng = SeededRNG(named: "http1.request-parser.random")
        for _ in 0 ..< iterations {
            let length = rng.below(301)
            var bytes: [UInt8] = []
            bytes.reserveCapacity(length)
            for _ in 0 ..< length { bytes.append(rng.byte()) }
            parseRequest(bytes)
        }
    }

    @Test
    func `RequestParser tolerates mutated and truncated valid requests`() {
        let report = fuzzNeverTraps(
            seed: .named("http1.request-parser.mutated"),
            iterations: iterations,
            corpus: {
                Array(
                    "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"
                        .utf8
                )
            },
            exercise: parseRequest
        )
        #expect(report.iterations == iterations)
    }

    @Test
    func `ChunkedDecoder tolerates mutated chunked bodies`() {
        let report = fuzzNeverTraps(
            seed: .named("http1.chunked-decoder.mutated"),
            iterations: iterations,
            corpus: { Array("5\r\nhello\r\n6\r\n world\r\n0\r\nX-T: v\r\n\r\n".utf8) },
            exercise: decodeChunked
        )
        #expect(report.iterations == iterations)
    }
}
