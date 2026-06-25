//
//  HTTP3FuzzTests.swift
//  HTTP3Tests
//
//  Seeded fuzzing: feed random and mutated bytes to every HTTP/3 sans-I/O decoder — the frame decoder
//  (RFC 9114 §7.1), the QPACK field-section decoder (RFC 9204), and the QUIC variable-length integer
//  codec (RFC 9000 §16) — and assert they NEVER trap. They may only return, return nil, or throw a
//  typed error. Reaching the end of a run is the assertion; fixed seeds keep failures reproducible.
//

import HTTPCore
import HTTPTestSupport
import QPACK
import Testing

@testable import HTTP3

@Suite("Fuzzing — HTTP/3 decoders never trap", .tags(.fuzz))
struct HTTP3FuzzTests {
    private let iterations = 4_000

    // MARK: Exercises — each may only return or throw, never trap or hang

    private func drainFrames(_ bytes: [UInt8]) {
        bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let decoder = HTTP3FrameDecoder(maxFrameSize: 1 << 20)
            do {
                while let frame = try decoder.nextFrame(&reader) {
                    _ = frame  // drained; reaching here repeatedly must never trap
                }
            }
            catch {
                // a typed HTTP3Error is fine — only a trap, hang, or OOM fails the run
            }
        }
    }

    private func decodeFieldSection(_ bytes: [UInt8]) {
        let decoder = QPACKDecoder()
        bytes.withUnsafeBytes { raw in
            _ = try? decoder.decode(raw.bytes)
        }
    }

    private func drainVarints(_ bytes: [UInt8]) {
        bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            var last = -1
            // Decode until no progress (nil on truncation leaves the position unchanged): never loops.
            while reader.position != last {
                last = reader.position
                _ = QUICVarint.decode(&reader)
            }
        }
    }

    // MARK: Random bytes

    @Test("the frame decoder tolerates arbitrary random bytes")
    func frameDecoderRandom() {
        var rng = SeededRNG(named: "http3.frame-decoder.random")
        for _ in 0 ..< iterations {
            drainFrames(Self.randomBytes(&rng))
        }
    }

    @Test("the QPACK decoder tolerates arbitrary random bytes")
    func qpackDecoderRandom() {
        var rng = SeededRNG(named: "http3.qpack-decoder.random")
        for _ in 0 ..< iterations {
            decodeFieldSection(Self.randomBytes(&rng))
        }
    }

    @Test("the QUIC varint codec tolerates arbitrary random bytes")
    func varintRandom() {
        var rng = SeededRNG(named: "http3.varint.random")
        for _ in 0 ..< iterations {
            drainVarints(Self.randomBytes(&rng))
        }
    }

    // MARK: Mutated valid corpora

    @Test("the frame decoder tolerates mutated valid frames")
    func frameDecoderMutated() {
        let report = fuzzNeverTraps(
            seed: .named("http3.frame-decoder.mutated"),
            iterations: iterations,
            corpus: {
                [0x00, 0x05] + Array("hello".utf8)  // a DATA frame: type 0x00, length 5
            },
            exercise: drainFrames
        )
        #expect(report.iterations == iterations)
    }

    @Test("the QPACK decoder tolerates a mutated valid field section")
    func qpackDecoderMutated() {
        let report = fuzzNeverTraps(
            seed: .named("http3.qpack-decoder.mutated"),
            iterations: iterations,
            corpus: {
                [0x00, 0x00]  // a well-formed empty field-section prefix (RIC 0, base 0)
            },
            exercise: decodeFieldSection
        )
        #expect(report.iterations == iterations)
    }

    @Test("the QUIC varint codec tolerates mutated valid varints")
    func varintMutated() {
        let report = fuzzNeverTraps(
            seed: .named("http3.varint.mutated"),
            iterations: iterations,
            corpus: {
                [0x25, 0x40, 0x19, 0x80, 0x01, 0x02, 0x03]  // 1-, 2-, and 4-octet forms
            },
            exercise: drainVarints
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
