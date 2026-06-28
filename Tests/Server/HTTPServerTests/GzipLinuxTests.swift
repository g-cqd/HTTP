//
//  GzipLinuxTests.swift
//  HTTPServerTests
//
//  Round-trips the Linux gzip content coding (GzipLinux over the CZlibCoding zlib shim): the encoder
//  produces a valid gzip member (RFC 1952 magic) that the shim's inflate recovers byte-for-byte, and the
//  member is smaller than compressible input. Gated `#if canImport(CZlibCoding)` — the Linux build graph;
//  on Darwin gzip is Apple's Compression, exercised by CompressionMiddlewareTests.
//

#if canImport(CZlibCoding)

    import Testing

    internal import CZlibCoding

    @testable import HTTPServer

    @Suite("Linux gzip content coding (zlib via CZlibCoding)")
    struct GzipLinuxTests {
        /// ~2.8 KiB of repetitive, highly compressible text.
        private let original = Array(
            String(repeating: "The quick brown fox jumps over the lazy dog.\n", count: 64).utf8
        )

        @Test("gzip encode → inflate round-trips byte-for-byte, emits RFC 1952 magic, and shrinks")
        func gzipRoundTrip() throws {
            let compressed = try #require(Gzip.compress(original), "zlib must produce a member")
            #expect(compressed.count < original.count, "compressible input must shrink")
            #expect(compressed.prefix(3) == [0x1f, 0x8b, 0x08], "RFC 1952 gzip magic + CM=deflate")

            var restored = [UInt8](repeating: 0, count: original.count + 64)
            let written = compressed.withUnsafeBufferPointer { source in
                restored.withUnsafeMutableBufferPointer { destination -> Int in
                    guard let src = source.baseAddress, let dst = destination.baseAddress else {
                        return 0
                    }
                    return czlib_inflate(dst, destination.count, src, source.count)
                }
            }
            restored.removeLast(restored.count - written)
            #expect(restored == original, "inflate must recover the original bytes exactly")
        }

        @Test("empty input yields nil (nothing to encode)")
        func emptyInputIsNil() {
            #expect(Gzip.compress([]) == nil)
        }
    }

#endif
