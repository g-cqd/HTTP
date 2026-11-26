//
//  ZstdCompressionStream.swift
//  HTTPZstd
//
//  Incremental Zstandard compression (RFC 8878): feed chunks with ``update(_:)``, close with ``finish()``. The frame
//  it produces is byte-identical to ``Zstd/compress(_:level:)`` of the concatenated chunks, however they were split.
//  The context comes from the shared pool and goes back to it when the stream finishes or is dropped mid-body.
//

/// One incremental Zstandard frame.
///
/// Single-use; not thread-safe.
public final class ZstdCompressionStream {
    private let level: Int
    private var compressor: ZstdCompressor?

    /// Starts a frame at `level`.
    public init(level: Int = Zstd.defaultLevel) throws(ZstdError) {
        self.level = level
        compressor = try Zstd.compressors.take(level) { level throws(ZstdError) in
            try ZstdCompressor(level: level)
        }
    }

    deinit {
        release()
    }

    /// Compresses `input`, returning the output ready so far (often empty: libzstd fills whole blocks).
    public func update(_ input: [UInt8]) throws(ZstdError) -> [UInt8] {
        guard let compressor else { throw .streamFinished }
        var output: [UInt8] = []
        do {
            try compressor.compress(input, end: false, into: &output)
        }
        catch {
            release()
            throw error
        }
        return output
    }

    /// Finishes the frame and returns its remaining bytes; the stream is spent afterwards.
    public func finish() throws(ZstdError) -> [UInt8] {
        guard let compressor else { throw .streamFinished }
        var output: [UInt8] = []
        defer { release() }
        try compressor.compress([], end: true, into: &output)
        return output
    }

    private func release() {
        guard let compressor else {
            return
        }
        self.compressor = nil
        compressor.reset()
        Zstd.compressors.give(level, compressor)
    }
}
