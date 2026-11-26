//
//  ZstdEncoderStream.swift
//  HTTPServer
//
//  The incremental `zstd` content coding (RFC 8878): ``ZstdCompressionStream`` behind the ``ContentEncoderStream``
//  seam. Its context returns to the shared pool when the body finishes, or when the stream is dropped because the
//  client went away mid-body.
//

internal import HTTPZstd

/// An incremental zstd frame (RFC 8878).
final class ZstdEncoderStream: ContentEncoderStream {
    private let stream: ZstdCompressionStream

    /// Starts a frame, or nil when no compression context can be had (memory).
    init?(level: Int) {
        guard let stream = try? ZstdCompressionStream(level: level) else {
            return nil
        }
        self.stream = stream
    }

    deinit {
        // The compression context returns to the pool when `stream` is released.
    }

    func update(_ input: [UInt8]) throws(ContentEncodingError) -> [UInt8] {
        do {
            return try stream.update(input)
        }
        catch .streamFinished {
            throw .streamFinished
        }
        catch {
            throw .encoderFailed
        }
    }

    func finish() throws(ContentEncodingError) -> [UInt8] {
        do {
            return try stream.finish()
        }
        catch .streamFinished {
            throw .streamFinished
        }
        catch {
            throw .encoderFailed
        }
    }
}
