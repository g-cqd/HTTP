//
//  ContentEncoderStreamTests.swift
//  HTTPServerTests
//
//  The incremental content-coding seam (RFC 9110 §8.4.1). The property that matters is that a coding
//  produced chunk-by-chunk is *the same octets* as the one-shot encoder produces for the concatenation
//  — otherwise the buffered and streamed paths of `CompressionMiddleware` would be two encoders, and a
//  cache keyed on `Vary: Accept-Encoding` could hold two different bodies for one representation.
//
//  Darwin's `compression_stream` buffers internally and flushes only at FINALIZE, so chunk boundaries
//  do not reach the output; these pin that, since it is an implementation property rather than an API
//  guarantee and a toolchain change could take it away silently.
//

import Testing

@testable import HTTPServer

/// Chunk sizes that straddle the encoders' internal windows, plus a degenerate 1-octet feed.
private let feedSizes: [Int] = [1, 64, 4_096, 65_536, 1_000_003]

/// A deterministic, semi-compressible payload — random enough not to be a degenerate run, repetitive
/// enough that the coding actually shrinks it.
private let payload: [UInt8] = {
    var seed: UInt64 = 0x9E37_79B9_7F4A_7C15
    var bytes: [UInt8] = []
    bytes.reserveCapacity(2_000_000)
    var line = 0
    while bytes.count < 2_000_000 {
        seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        bytes.append(contentsOf: Array("line \(line) payload \(line % 97) \(seed >> 60)\n".utf8))
        line += 1
    }
    return bytes
}()

/// Feeds `payload` through a fresh encoder stream in `size`-octet chunks.
private func streamed(
    _ encoder: any StreamingContentEncoder,
    chunk size: Int
) throws -> [UInt8]? {
    guard let stream = encoder.makeStream() else {
        return nil
    }
    var output: [UInt8] = []
    for start in stride(from: 0, to: payload.count, by: size) {
        let chunk = Array(payload[start ..< min(start + size, payload.count)])
        output.append(contentsOf: try stream.update(chunk))
    }
    output.append(contentsOf: try stream.finish())
    return output
}

@Test(
    "RFC 9110 §8.4.1 — a chunked gzip stream is byte-identical to the one-shot member",
    arguments: feedSizes
)
func gzipStreamMatchesOneShot(chunk: Int) throws {
    let encoder = GzipEncoder()
    #expect(try streamed(encoder, chunk: chunk) == encoder.encode(payload))
}

@Test(
    "RFC 9110 §8.4.1 — a chunked Brotli stream is byte-identical to the one-shot stream",
    arguments: feedSizes
)
func brotliStreamMatchesOneShot(chunk: Int) throws {
    let encoder = BrotliEncoder()
    #expect(try streamed(encoder, chunk: chunk) == encoder.encode(payload))
}

@Test("RFC 1952 — an empty streamed gzip member still carries a header and a trailer")
func gzipStreamOfNothingIsAValidMember() throws {
    let stream = try #require(GzipEncoder().makeStream())
    let member = try stream.finish()
    #expect(member.prefix(3) == [0x1F, 0x8B, 0x08])
    // 10-octet header + the empty-deflate block + CRC-32 of "" (0) and ISIZE 0.
    #expect(member.suffix(8) == [0, 0, 0, 0, 0, 0, 0, 0])
}

@Test("RFC 9110 §8.4.1 — a finished encoder stream refuses further input")
func finishedStreamRefusesMoreInput() throws {
    let stream = try #require(GzipEncoder().makeStream())
    _ = try stream.finish()
    #expect(throws: ContentEncodingError.streamFinished) {
        _ = try stream.update([0x41])
    }
}

@Test("RFC 8878 — the zstd coding declares no streaming form, so it falls through to identity")
func zstdDoesNotStream() {
    #expect(ZstdEncoder() as? any StreamingContentEncoder == nil)
}
