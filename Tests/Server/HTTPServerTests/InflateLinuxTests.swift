//
//  InflateLinuxTests.swift
//  HTTPServerTests
//
//  Exercises the Linux inbound decoders (InflateLinux over the CZlibCoding zlib shim): a gzip body
//  round-trips through encode → decode, and a body that would decode past the cap fails closed (the
//  decompression-bomb defense, CWE-409). Gated `#if canImport(CZlibCoding)` — the Linux build graph; on
//  Darwin inbound decode is Apple's Compression, exercised by DecompressionMiddlewareTests.
//

#if canImport(CZlibCoding)

    import Testing

    @testable import HTTPServer

    @Suite("Linux inbound decompression (zlib via CZlibCoding)")
    struct InflateLinuxTests {
        /// ~2.8 KiB of highly compressible text.
        private let original = Array(
            String(repeating: "The quick brown fox jumps over the lazy dog.\n", count: 64).utf8
        )

        @Test("a gzip body round-trips through encode → Inflate.decompress")
        func gzipInbound() throws {
            let coded = try #require(Gzip.compress(original), "zlib must encode")
            let decoded = try #require(
                Inflate.decompress(coded, encoding: "gzip", maxOutput: 1 << 20),
                "the gzip member must decode"
            )
            #expect(decoded == original)
        }

        @Test("a gzip body decoding past the cap fails closed (decompression bomb, CWE-409)")
        func gzipBombCapped() throws {
            let coded = try #require(Gzip.compress(original), "zlib must encode")
            // The member decodes to ~2.8 KiB; a cap well below that must reject it, never buffer it.
            #expect(Inflate.decompress(coded, encoding: "gzip", maxOutput: 256) == nil)
        }

        @Test("malformed / undecodable input is rejected (nil), never a partial body")
        func malformedRejected() {
            let garbage = Array("not a gzip member".utf8)
            #expect(Inflate.decompress(garbage, encoding: "gzip", maxOutput: 1 << 20) == nil)
        }
    }

#endif
