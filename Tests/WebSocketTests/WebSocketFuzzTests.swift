//
//  WebSocketFuzzTests.swift
//  WebSocketTests
//
//  Seeded fuzzing: feed random and mutated bytes to the WebSocket frame decoder and the sans-I/O
//  connection engine (RFC 6455 §5/§6) and assert they NEVER trap — only return, return nil, or throw
//  a typed WebSocketError. Reaching the end of a run is the assertion; fixed seeds keep failures
//  reproducible.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import WebSocket

@Suite("Fuzzing — WebSocket decoders never trap", .tags(.fuzz))
struct WebSocketFuzzTests {
    private let iterations = 4_000

    // MARK: Exercises — each may only return or throw, never trap

    private func drainFrames(_ bytes: [UInt8]) {
        bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let decoder = WebSocketFrameDecoder(requireMaskedFrames: true)
            do {
                while let frame = try decoder.nextFrame(&reader) {
                    _ = frame  // drained; reaching here repeatedly must never trap
                }
            }
            catch {
                // a typed WebSocketError is fine — only a trap, hang, or OOM fails the run
            }
        }
    }

    private func feedConnection(_ bytes: [UInt8]) {
        var connection = WebSocketConnection()
        _ = try? connection.receive(bytes)
    }

    // MARK: Random bytes

    @Test("the frame decoder tolerates arbitrary random bytes")
    func frameDecoderRandom() {
        var rng = SeededRNG(named: "websocket.frame-decoder.random")
        for _ in 0 ..< iterations {
            drainFrames(Self.randomBytes(&rng))
        }
    }

    @Test("the connection engine tolerates arbitrary random bytes")
    func connectionRandom() {
        var rng = SeededRNG(named: "websocket.connection.random")
        for _ in 0 ..< iterations {
            feedConnection(Self.randomBytes(&rng))
        }
    }

    // MARK: Mutated valid corpora

    @Test("the frame decoder tolerates mutated valid frames")
    func frameDecoderMutated() {
        let report = fuzzNeverTraps(
            seed: .named("websocket.frame-decoder.mutated"),
            iterations: iterations,
            corpus: {
                Self.maskedFrame(.text, Array("hello".utf8))
            },
            exercise: drainFrames
        )
        #expect(report.iterations == iterations)
    }

    @Test("the connection engine tolerates a mutated valid text + ping sequence")
    func connectionMutated() {
        let report = fuzzNeverTraps(
            seed: .named("websocket.connection.mutated"),
            iterations: iterations,
            corpus: {
                Self.maskedFrame(.text, Array("hi".utf8)) + Self.maskedFrame(.ping, [0x01])
            },
            exercise: feedConnection
        )
        #expect(report.iterations == iterations)
    }

    // MARK: Fixtures

    /// A masked client frame (RFC 6455 §5.1/§5.3) for payloads up to 125 octets.
    private static func maskedFrame(_ opcode: WebSocketOpcode, _ payload: [UInt8]) -> [UInt8] {
        let key: [UInt8] = [0x12, 0x34, 0x56, 0x78]
        var wire: [UInt8] = [0x80 | opcode.rawValue, 0x80 | UInt8(payload.count)]
        wire += key
        for (index, byte) in payload.enumerated() {
            wire.append(byte ^ key[index & 0x3])
        }
        return wire
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
