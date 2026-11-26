//
//  Zstd.swift
//  HTTPZstd
//
//  Zstandard (RFC 8878) over the vendored libzstd (`CHTTPZstd`). Encoding always goes through a stream that writes no
//  content size, so a body coded whole (``compress(_:level:)``) and coded in chunks (``ZstdCompressionStream``) is the
//  same frame byte for byte — the guarantee a `Vary: Accept-Encoding` cache relies on. Decoding is bounded: by the
//  caller's output limit, and by a window limit derived from it, so a hostile header can make it allocate neither
//  more output nor a larger window than the caller accepted.
//

internal import CHTTPZstd

/// Zstandard compression and decompression (RFC 8878).
public enum Zstd {
    /// The compression levels accepted (libzstd's negative "fast" levels are not offered).
    public static let levels: ClosedRange<Int> = 1 ... 19
    /// The default level, libzstd's: about 3.5 MiB of context per concurrent stream (level 9 needs 17 MiB).
    public static let defaultLevel = 3

    static let compressors = ZstdContextPool<ZstdCompressor>(capacity: 4)
    static let decompressors = ZstdContextPool<ZstdDecompressor>(capacity: 4)

    /// Whether `bytes` starts with the Zstandard frame magic number (`28 B5 2F FD`, RFC 8878 §3.1.1).
    public static func isFrame(_ bytes: [UInt8]) -> Bool {
        bytes.count >= 4 && bytes[0] == 0x28 && bytes[1] == 0xB5 && bytes[2] == 0x2F
            && bytes[3] == 0xFD
    }

    /// Compresses `input` into one frame at `level`.
    public static func compress(
        _ input: [UInt8], level: Int = defaultLevel
    ) throws(ZstdError) -> [UInt8] {
        let compressor = try compressors.take(level) { level throws(ZstdError) in
            try ZstdCompressor(level: level)
        }
        var output: [UInt8] = []
        do {
            try compressor.compress(input, end: true, into: &output)
        }
        catch {
            compressor.context.reset()
            compressors.give(level, compressor)
            throw error
        }
        compressor.context.reset()
        compressors.give(level, compressor)
        return output
    }

    /// Decompresses every frame of `input` (skippable frames included) into at most `maxOutputSize` bytes.
    ///
    /// - Throws: ``ZstdError/corrupt`` for anything that is not well-formed Zstandard, ``ZstdError/truncated``,
    ///   ``ZstdError/outputLimitExceeded`` past `maxOutputSize`, ``ZstdError/windowTooLarge`` for a window larger
    ///   than both 8 MiB (RFC 9659's limit for the `zstd` content coding) and `maxOutputSize`.
    public static func decompress(_ input: [UInt8], maxOutputSize: Int) throws(ZstdError) -> [UInt8]
    {
        guard maxOutputSize >= 0 else { throw .outputLimitExceeded }
        let declared = input.withUnsafeBufferPointer { bytes in
            unsafe chttpzstd_frame_content_size(bytes.baseAddress, bytes.count)
        }
        if declared == UInt64.max - 1 { throw .corrupt }
        let known = declared == UInt64.max ? nil : declared
        if let known, known > UInt64(maxOutputSize) { throw .outputLimitExceeded }
        let windowLogMax = windowLog(for: maxOutputSize)
        let decompressor = try decompressors.take(windowLogMax) { log throws(ZstdError) in
            try ZstdDecompressor(windowLogMax: log)
        }
        defer {
            decompressor.context.reset()
            decompressors.give(windowLogMax, decompressor)
        }
        let size = known.map { Int($0) }
        return try decompressor.decompress(input, declared: size, limit: maxOutputSize)
    }

    /// The largest window to accept for `limit` bytes of output: at least 2^23 (RFC 9659 §3), at most 2^27.
    static func windowLog(for limit: Int) -> Int {
        let needed = limit <= 1 ? 1 : Int.bitWidth - (limit - 1).leadingZeroBitCount
        return min(max(needed, 23), 27)
    }
}
