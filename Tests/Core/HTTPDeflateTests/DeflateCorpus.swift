//
//  DeflateCorpus.swift
//  HTTPDeflateTests
//
//  The shared payload corpus for the round-trip and differential suites: the shapes that exercise
//  DEFLATE's distinct machinery — empty/tiny inputs, distance-1 runs, 258-octet matches, ASCII text
//  (fixed-vs-dynamic pressure), incompressible seeded noise (stored pressure), and structured
//  binary. Seeded, so every machine sees the same octets.
//

internal import HTTPDeflate
internal import HTTPTestSupport

/// A shared, seeded payload corpus and small bit-stream builder for handcrafted vectors.
enum DeflateCorpus {
    /// A named payload for parameterized suites.
    struct Payload: CustomStringConvertible {
        let label: String
        let bytes: [UInt8]

        var description: String {
            "\(label) (\(bytes.count) octets)"
        }
    }

    /// The standard corpus: every DEFLATE-relevant shape, small enough for CI.
    static func standard() -> [Payload] {
        var generator = SeededRNG(seed: Seed.named("httpdeflate.corpus"))
        return [
            Payload(label: "empty", bytes: []),
            Payload(label: "one octet", bytes: [0x61]),
            Payload(label: "two octets", bytes: [0x61, 0x62]),
            Payload(label: "minMatch run", bytes: [UInt8](repeating: 0x41, count: 3)),
            Payload(label: "distance-1 run", bytes: [UInt8](repeating: 0x7A, count: 300)),
            Payload(
                label: "258-length matches",
                bytes: [UInt8](repeating: 0x42, count: 258 * 4 + 7)
            ),
            Payload(label: "ascii text", bytes: text(16_384)),
            Payload(label: "binary pattern", bytes: (0 ..< 8_192).map { UInt8($0 & 0xFF) }),
            Payload(label: "random noise 4K", bytes: random(4_096, using: &generator)),
            Payload(label: "random noise 100K", bytes: random(100_000, using: &generator)),
            Payload(label: "text 300K (multi-block, window slide)", bytes: text(300_000)),
            Payload(
                label: "alternating noise/text",
                bytes: random(20_000, using: &generator) + text(20_000)
                    + random(20_000, using: &generator)
            )
        ]
    }

    /// Repetitive-but-structured ASCII, the compressible middle of the corpus.
    static func text(_ count: Int) -> [UInt8] {
        let phrase = Array("The quick brown fox jumps over the lazy dog 0123456789.\n".utf8)
        var output: [UInt8] = []
        output.reserveCapacity(count)
        var line = 0
        while output.count < count {
            output.append(contentsOf: phrase)
            output.append(contentsOf: Array("line \(line)\n".utf8))
            line += 1
        }
        output.removeLast(output.count - count)
        return output
    }

    /// Seeded incompressible noise.
    static func random(_ count: Int, using generator: inout SeededRNG) -> [UInt8] {
        (0 ..< count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }

    /// The compression levels every round-trip suite sweeps.
    static let levels: [DeflateLevel] = [.store, .fast, .balanced]

    /// A little LSB-first bit packer for handcrafting RFC 1951 vectors in tests.
    struct BitStream {
        private var bytes: [UInt8] = []
        private var buffer = 0
        private var filled = 0

        /// Appends the low `width` bits of `value`, LSB first (§3.1.1 non-Huffman packing).
        mutating func bits(_ value: Int, _ width: Int) {
            buffer |= value << filled
            filled += width
            while filled >= 8 {
                bytes.append(UInt8(buffer & 0xFF))
                buffer >>= 8
                filled -= 8
            }
        }

        /// Appends a Huffman code MSB first (§3.1.1 code packing).
        mutating func code(_ value: Int, _ width: Int) {
            var reversed = 0
            var input = value
            for _ in 0 ..< width {
                reversed = (reversed << 1) | (input & 1)
                input >>= 1
            }
            bits(reversed, width)
        }

        /// Zero-pads to a byte boundary.
        mutating func align() {
            if filled > 0 {
                bits(0, 8 - filled)
            }
        }

        /// The packed octets (final partial byte zero-padded).
        var output: [UInt8] {
            var flushed = self
            flushed.align()
            return flushed.bytes
        }
    }
}
