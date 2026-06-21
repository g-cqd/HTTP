//
//  FuzzTests.swift
//  HTTP1Tests
//
//  Deterministic fuzzing: feed random and mutated bytes to every HTTP/1.1 parser and assert they
//  NEVER trap — they may only return a value or throw a typed `HTTP1ParseError`. Reaching the end
//  of each loop (the process did not crash) is the assertion. A fixed seed keeps failures reproducible.
//

import HTTPCore
import Testing

@testable import HTTP1

/// A small, seedable SplitMix64 generator so fuzz runs are deterministic and reproducible.
private struct SeededGenerator: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) { self.state = seed }

    mutating func next() -> UInt64 {
        state = state &+ 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

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

@Suite("Fuzzing — parsers never trap, only return or throw")
struct FuzzTests {

    private let iterations = 4000

    @Test("RequestParser tolerates arbitrary random bytes")
    func requestParserRandomBytes() {
        var rng = SeededGenerator(seed: 0xDEAD_BEEF)
        var completed = 0
        for _ in 0..<iterations {
            let length = Int.random(in: 0...300, using: &rng)
            var bytes = [UInt8]()
            bytes.reserveCapacity(length)
            for _ in 0..<length { bytes.append(UInt8.random(in: 0...255, using: &rng)) }
            parseRequest(bytes)
            completed += 1
        }
        #expect(completed == iterations)
    }

    @Test("RequestParser tolerates mutated and truncated valid requests")
    func requestParserMutatedValid() {
        let template = Array(
            "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello".utf8)
        var rng = SeededGenerator(seed: 0x0BAD_F00D)
        var completed = 0
        for _ in 0..<iterations {
            var bytes = template
            for _ in 0..<Int.random(in: 0...10, using: &rng) where !bytes.isEmpty {
                bytes[Int.random(in: 0..<bytes.count, using: &rng)] = UInt8.random(
                    in: 0...255, using: &rng)
            }
            if Bool.random(using: &rng), !bytes.isEmpty {
                bytes = Array(bytes.prefix(Int.random(in: 0..<bytes.count, using: &rng)))
            }
            parseRequest(bytes)
            completed += 1
        }
        #expect(completed == iterations)
    }

    @Test("ChunkedDecoder tolerates mutated chunked bodies")
    func chunkedDecoderMutated() {
        let template = Array("5\r\nhello\r\n6\r\n world\r\n0\r\nX-T: v\r\n\r\n".utf8)
        var rng = SeededGenerator(seed: 0xFEED_FACE)
        var completed = 0
        for _ in 0..<iterations {
            var bytes = template
            for _ in 0..<Int.random(in: 0...8, using: &rng) where !bytes.isEmpty {
                bytes[Int.random(in: 0..<bytes.count, using: &rng)] = UInt8.random(
                    in: 0...255, using: &rng)
            }
            decodeChunked(bytes)
            completed += 1
        }
        #expect(completed == iterations)
    }
}
