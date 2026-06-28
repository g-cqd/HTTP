//
//  CBrotliTests.swift
//  HTTPServerTests
//
//  Round-trips the Brotli content coding through the CBrotli libbrotli shim: compress → decompress
//  recovers the input byte-for-byte and shrinks compressible data, and an over-cap decode fails closed
//  (the decompression-bomb defense, CWE-409). Gated `#if canImport(CBrotli)` — the opt-in `HTTP_BROTLI`
//  build (libbrotli present): on macOS via Homebrew `brotli`, on Linux via `libbrotli-dev` in CI.
//

#if canImport(CBrotli)

    import Testing

    internal import CBrotli

    @Suite("Brotli content coding (libbrotli via CBrotli)")
    struct CBrotliTests {
        /// ~1.6 KiB of highly compressible text.
        private let original = Array(
            String(repeating: "The quick brown fox jumps over the lazy dog.\n", count: 36).utf8
        )

        private func compress(_ input: [UInt8], quality: Int32 = 5) -> [UInt8]? {
            let bound = cbrotli_compress_bound(input.count)
            guard bound > 0 else {
                return nil
            }
            var out = [UInt8](repeating: 0, count: bound)
            let written = input.withUnsafeBufferPointer { source in
                out.withUnsafeMutableBufferPointer { destination -> Int in
                    guard let source = source.baseAddress, let destination = destination.baseAddress
                    else {
                        return 0
                    }
                    return cbrotli_compress(destination, bound, source, input.count, quality)
                }
            }
            guard written > 0 else {
                return nil
            }
            out.removeLast(out.count - written)
            return out
        }

        private func decompress(_ input: [UInt8], cap: Int) -> [UInt8]? {
            let capacity = cap + 1
            var out = [UInt8](repeating: 0, count: capacity)
            let written = input.withUnsafeBufferPointer { source in
                out.withUnsafeMutableBufferPointer { destination -> Int in
                    guard let source = source.baseAddress, let destination = destination.baseAddress
                    else {
                        return 0
                    }
                    return cbrotli_decompress(destination, capacity, source, input.count)
                }
            }
            guard written > 0, written <= cap else {
                return nil
            }
            out.removeLast(out.count - written)
            return out
        }

        @Test("brotli compress → decompress round-trips byte-for-byte and shrinks")
        func roundTrip() throws {
            let compressed = try #require(compress(original), "libbrotli must encode")
            #expect(compressed.count < original.count, "compressible input must shrink")
            let restored = try #require(
                decompress(compressed, cap: 1 << 20), "the stream must decode"
            )
            #expect(restored == original)
        }

        @Test("a brotli stream decoding past the cap fails closed (decompression bomb, CWE-409)")
        func bombCapped() throws {
            let compressed = try #require(compress(original), "libbrotli must encode")
            #expect(decompress(compressed, cap: 128) == nil, "an over-cap decode must be rejected")
        }
    }

#endif
