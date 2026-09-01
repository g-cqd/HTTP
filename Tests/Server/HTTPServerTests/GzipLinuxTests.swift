//
//  GzipLinuxTests.swift
//  HTTPServerTests
//
//  Round-trips the Linux gzip content coding (GzipLinux over the in-house HTTPDeflate codec): the
//  encoder produces a valid gzip member (RFC 1952 magic) that decodes back byte-for-byte, and the
//  member is smaller than compressible input. Gated `#if !canImport(Compression)` — the Linux build
//  graph; on Darwin gzip is Apple's Compression, exercised by CompressionMiddlewareTests. The
//  decode oracle is HTTPDeflate's own verified decoder, whose zlib equivalence is proven by the
//  codec's differential suite.
//

#if !canImport(Compression)

    internal import HTTPDeflate
    import Testing

    @testable import HTTPServer

    @Suite("Linux gzip content coding (in-house HTTPDeflate)")
    struct GzipLinuxTests {
        /// ~2.8 KiB of repetitive, highly compressible text.
        private let original = Array(
            String(repeating: "The quick brown fox jumps over the lazy dog.\n", count: 64).utf8
        )

        @Test("gzip encode → decode round-trips byte-for-byte, emits RFC 1952 magic, and shrinks")
        func gzipRoundTrip() throws {
            let compressed = try #require(Gzip.compress(original), "the codec must encode")
            #expect(compressed.count < original.count, "compressible input must shrink")
            #expect(compressed.prefix(3) == [0x1F, 0x8B, 0x08], "RFC 1952 gzip magic + CM=deflate")
            let restored = DeflateCodec.decompress(
                compressed, format: .gzip, capacity: original.count + 64
            )
            #expect(restored == original, "decode must recover the original bytes exactly")
        }

        @Test("empty input yields nil (nothing to encode)")
        func emptyInputIsNil() {
            #expect(Gzip.compress([]) == nil)
        }
    }

#endif
