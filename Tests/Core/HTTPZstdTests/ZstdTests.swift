//
//  ZstdTests.swift
//  HTTPZstdTests
//
//  The vendored Zstandard codec (RFC 8878) through HTTPZstd: round-trips across levels and shapes, chunking
//  invariance of the stream encoder, the bounded decoder's limits (declared and undeclared sizes, windows), and
//  hostile input — truncations, corruption, trailing garbage — failing with a typed error, never a trap.
//

import Testing

@testable import HTTPZstd

@Suite("Zstd — the vendored libzstd codec (RFC 8878)")
struct ZstdTests {
    private static func payload(_ count: Int, seed: UInt64) -> [UInt8] {
        let text = "the zstandard frame block literal sequence offset window match swift http "
        let words = Array(text.utf8)
        var state = seed &+ 0x9E37_79B9_7F4A_7C15
        return (0 ..< count)
            .map { index in
                state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
                return index % 97 < 80
                    ? words[Int(state >> 33) % words.count] : UInt8(truncatingIfNeeded: state >> 40)
            }
    }

    @Test("round-trips every size and level")
    func roundTrips() throws {
        for level in [1, 3, 9, 19] {
            for size in [0, 1, 31, 4_096, 131_073, 1_000_000] {
                let input = Self.payload(size, seed: UInt64(size + level))
                let frame = try Zstd.compress(input, level: level)
                #expect(Zstd.isFrame(frame))
                #expect(
                    try Zstd.decompress(frame, maxOutputSize: size) == input,
                    "level \(level) size \(size)")
            }
        }
    }

    @Test("a stream is byte-identical to the one-shot frame, however the input is chunked")
    func streamMatchesOneShot() throws {
        for (size, chunk) in [
            (3_000, 1), (300_000, 13), (600_000, 4_096), (600_000, 65_537), (600_000, 600_000)
        ] {
            let input = Self.payload(size, seed: 7)
            let whole = try Zstd.compress(input)
            let stream = try ZstdCompressionStream()
            var frame: [UInt8] = []
            var offset = 0
            while offset < input.count {
                let end = min(offset + chunk, input.count)
                frame += try stream.update(Array(input[offset ..< end]))
                offset = end
            }
            frame += try stream.finish()
            #expect(frame == whole, "size \(size) chunk \(chunk)")
            #expect(throws: ZstdError.streamFinished) { try stream.update([1]) }
        }
    }

    @Test("decoding is bounded by the caller's limit, declared size or not")
    func boundedDecoding() throws {
        let input = Self.payload(100_000, seed: 3)
        let frame = try Zstd.compress(input)  // no declared size: the decoder must stop on its own
        #expect(try Zstd.decompress(frame, maxOutputSize: 100_000).count == 100_000)
        #expect(throws: ZstdError.outputLimitExceeded) {
            try Zstd.decompress(frame, maxOutputSize: 99_999)
        }
        #expect(throws: ZstdError.outputLimitExceeded) {
            try Zstd.decompress(frame, maxOutputSize: 10)
        }
        // A frame that declares its size is refused before decoding when the size is over the limit.
        let declared: [UInt8] = [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0xFF, 0x01, 0x00, 0x00]
        #expect(throws: ZstdError.outputLimitExceeded) {
            try Zstd.decompress(declared, maxOutputSize: 100)
        }
    }

    @Test("concatenated and skippable frames decode as one content")
    func multipleFrames() throws {
        let first = Self.payload(5_000, seed: 1)
        let second = Self.payload(70_000, seed: 2)
        let skippable: [UInt8] = [0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 9, 9, 9]
        let joined = try Zstd.compress(first) + skippable + Zstd.compress(second, level: 1)
        #expect(try Zstd.decompress(joined, maxOutputSize: 1 << 20) == first + second)
    }

    @Test("hostile input fails with a typed error, never a trap")
    func hostileInput() throws {
        let frame = try Zstd.compress(Self.payload(50_000, seed: 9))
        for length in stride(from: 0, to: frame.count, by: max(1, frame.count / 200)) {
            #expect(throws: ZstdError.self) {
                try Zstd.decompress(Array(frame.prefix(length)), maxOutputSize: 1 << 20)
            }
        }
        #expect(throws: ZstdError.corrupt) {
            try Zstd.decompress(Array("not zstd".utf8), maxOutputSize: 100)
        }
        #expect(throws: ZstdError.self) {
            try Zstd.decompress(frame + [1, 2, 3, 4, 5], maxOutputSize: 1 << 20)
        }
        var state: UInt64 = 42
        for _ in 0 ..< 300 {
            var corrupted = frame
            state = state &* 6_364_136_223_846_793_005 &+ 1
            let at = 4 + Int(state >> 33) % (corrupted.count - 4)
            corrupted[at] ^= UInt8(truncatingIfNeeded: state >> 20) | 1
            _ = try? Zstd.decompress(corrupted, maxOutputSize: 1 << 20)
        }
    }

    @Test("a window larger than the limit allows is refused before allocation (RFC 9659 §3)")
    func windowLimit() throws {
        #expect(Zstd.windowLog(for: 1_000) == 23)
        #expect(Zstd.windowLog(for: 16 << 20) == 24)
        #expect(Zstd.windowLog(for: Int.max) == 27)
        // Window descriptor 0x90: a 2^28-byte window, above the 2^23 a 1 MiB limit allows; no content size declared.
        let huge: [UInt8] = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x90, 0x01, 0x00, 0x00]
        #expect(throws: ZstdError.windowTooLarge) {
            try Zstd.decompress(huge, maxOutputSize: 1 << 20)
        }
    }

    @Test("invalid levels are rejected")
    func levels() {
        #expect(throws: ZstdError.invalidLevel(0)) { try Zstd.compress([1], level: 0) }
        #expect(throws: ZstdError.invalidLevel(20)) { try ZstdCompressionStream(level: 20) }
    }

    @Test("concurrent encodes and decodes share the pool safely")
    func concurrency() async throws {
        let inputs = (0 ..< 32).map { Self.payload(20_000 + $0 * 997, seed: UInt64($0)) }
        try await withThrowingTaskGroup(of: Bool.self) { group in
            for input in inputs {
                group.addTask {
                    let frame = try Zstd.compress(input)
                    return try Zstd.decompress(frame, maxOutputSize: input.count) == input
                }
            }
            for try await ok in group { #expect(ok) }
        }
    }
}
