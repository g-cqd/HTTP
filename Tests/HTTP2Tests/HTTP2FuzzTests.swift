//
//  HTTP2FuzzTests.swift
//  HTTP2Tests
//
//  Seeded fuzzing: feed random and mutated bytes to every HTTP/2 sans-I/O decoder and assert they
//  NEVER trap — they may only return, return nil, or throw a typed HTTP2Error / HPACKError. Reaching
//  the end of a run (the process did not crash, hang, or OOM) is the assertion; fixed seeds keep any
//  failure reproducible. Reuses the `H2Wire` frame builders for the mutated corpora.
//

import HPACK
import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP2

@Suite("Fuzzing — HTTP/2 decoders never trap", .tags(.fuzz))
struct HTTP2FuzzTests {
    private let iterations = 4_000

    // MARK: Exercises — each may only return or throw, never trap

    private func drainFrames(_ bytes: [UInt8]) {
        bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let decoder = HTTP2FrameDecoder()
            do {
                while let frame = try decoder.nextFrame(&reader) {
                    _ = frame  // drained; reaching here repeatedly must never trap
                }
            }
            catch {
                // a typed HTTP2Error is fine — only a trap, hang, or OOM fails the run
            }
        }
    }

    private func decodeHeaderBlock(_ bytes: [UInt8]) {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        bytes.withUnsafeBytes { raw in
            _ = try? decoder.decode(raw.bytes)
        }
    }

    private func feedConnection(_ bytes: [UInt8]) {
        var connection = HTTP2Connection(limits: .default)
        _ = connection.outboundBytes()
        _ = try? connection.receive(bytes)
    }

    // MARK: Random bytes

    @Test("the frame decoder tolerates arbitrary random bytes")
    func frameDecoderRandom() {
        var rng = SeededRNG(named: "http2.frame-decoder.random")
        for _ in 0 ..< iterations {
            drainFrames(Self.randomBytes(&rng))
        }
    }

    @Test("the HPACK decoder tolerates arbitrary random bytes")
    func hpackDecoderRandom() {
        var rng = SeededRNG(named: "http2.hpack-decoder.random")
        for _ in 0 ..< iterations {
            decodeHeaderBlock(Self.randomBytes(&rng))
        }
    }

    @Test("the connection engine tolerates arbitrary random bytes")
    func connectionRandom() {
        var rng = SeededRNG(named: "http2.connection.random")
        for _ in 0 ..< iterations {
            feedConnection(Self.randomBytes(&rng))
        }
    }

    // MARK: Mutated valid corpora

    @Test("the frame decoder tolerates mutated valid frames")
    func frameDecoderMutated() {
        let report = fuzzNeverTraps(
            seed: .named("http2.frame-decoder.mutated"),
            iterations: iterations,
            corpus: {
                H2Wire.get(streamID: 1)
                    + H2Wire.data(streamID: 1, payload: Array("hi".utf8))
            },
            exercise: drainFrames
        )
        #expect(report.iterations == iterations)
    }

    @Test("the HPACK decoder tolerates mutated valid header blocks")
    func hpackDecoderMutated() {
        let report = fuzzNeverTraps(
            seed: .named("http2.hpack-decoder.mutated"),
            iterations: iterations,
            corpus: { H2Wire.headerBlock(H2Wire.requestFields()) },
            exercise: decodeHeaderBlock
        )
        #expect(report.iterations == iterations)
    }

    @Test("the connection engine tolerates a mutated valid handshake + request")
    func connectionMutated() {
        let report = fuzzNeverTraps(
            seed: .named("http2.connection.mutated"),
            iterations: iterations,
            corpus: {
                H2Wire.clientPreface + H2Wire.settings() + H2Wire.get(streamID: 1)
            },
            exercise: feedConnection
        )
        #expect(report.iterations == iterations)
    }

    private static func randomBytes(_ rng: inout SeededRNG) -> [UInt8] {
        let length = rng.below(301)
        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        for _ in 0 ..< length {
            bytes.append(rng.byte())
        }
        return bytes
    }
}
