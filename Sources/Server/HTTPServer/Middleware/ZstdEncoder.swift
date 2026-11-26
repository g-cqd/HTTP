//
//  ZstdEncoder.swift
//  HTTPServer
//
//  The `zstd` content coding (RFC 8878, RFC 9659) as a ``StreamingContentEncoder``, over the vendored libzstd
//  (`HTTPZstd`), so it is available on every build. The coding is a single raw zstd frame with no envelope. The
//  buffered and streamed paths share one encoder that writes no content size, so a resource coded either way is the
//  same representation byte for byte; at the default level 3 its window is 2 MiB, within RFC 9659's 8 MiB.
//

internal import HTTPZstd

/// The `zstd` content coding (RFC 8878).
public struct ZstdEncoder: StreamingContentEncoder {
    /// The `zstd` content-coding token (RFC 9110 §8.4.1).
    public let token = "zstd"
    /// The compression level, from 1 to 19.
    public let level: Int

    /// Creates the encoder at `level` (libzstd's default 3: about 3.5 MiB of context per concurrent response).
    public init(level: Int = 3) {
        self.level = min(max(level, 1), 19)
    }

    /// Encodes `body` as a zstd frame, or `nil` for an empty body (nothing to encode) or an encoder failure.
    public func encode(_ body: [UInt8]) -> [UInt8]? {
        guard !body.isEmpty else {
            return nil
        }
        return try? Zstd.compress(body, level: level)
    }

    /// An incremental zstd frame, byte-identical to ``encode(_:)`` of the whole body.
    public func makeStream() -> (any ContentEncoderStream)? {
        ZstdEncoderStream(level: level)
    }
}
