//
//  GzipEncoder.swift
//  HTTPServer
//
//  The `gzip` content coding (RFC 1952) as a ``ContentEncoder`` — Darwin Compression, or the Linux zlib
//  shim (`CZlibCoding`); `nil` on a build with neither backend (Phase 3.3).
//

/// The `gzip` content coding (RFC 1952).
public struct GzipEncoder: StreamingContentEncoder {
    /// The `gzip` content-coding token (RFC 9110 §8.4.1).
    public let token = "gzip"

    /// Creates the encoder.
    public init() {
        // Stateless.
    }

    /// Encodes `body` as a gzip member, or `nil` on a build with no gzip backend.
    public func encode(_ body: [UInt8]) -> [UInt8]? {
        #if canImport(Compression) || canImport(CZlibCoding)
            return Gzip.compress(body)
        #else
            return nil
        #endif
    }

    /// An incremental gzip member, on every build that can produce a buffered one.
    ///
    /// The condition here and the one on ``encode(_:)`` are deliberately the same expression, and
    /// `ContentEncoderStreamTests` asserts that they agree. A coding that can encode but cannot stream
    /// serves streamed responses **uncoded** (never buffered and coded — see
    /// ``StreamingContentEncoder``), which is a silent downgrade for exactly the bodies most worth
    /// coding: SSE, chunked downloads, and every static file over the streaming threshold. Darwin
    /// streams through `compression_stream`, Linux through the `CZlibCoding` shim's resumable
    /// `deflate`; each is byte-identical to its own platform's buffered path.
    public func makeStream() -> (any ContentEncoderStream)? {
        #if canImport(Compression) || canImport(CZlibCoding)
            return GzipEncoderStream()
        #else
            return nil
        #endif
    }
}
