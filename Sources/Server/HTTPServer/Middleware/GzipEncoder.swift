//
//  GzipEncoder.swift
//  HTTPServer
//
//  The `gzip` content coding (RFC 1952) as a ``ContentEncoder`` — Darwin Compression, or the
//  in-house HTTPDeflate codec everywhere else. Every build has a gzip backend now, so neither
//  entry point can return nil for want of one.
//

/// The `gzip` content coding (RFC 1952).
public struct GzipEncoder: StreamingContentEncoder {
    /// The `gzip` content-coding token (RFC 9110 §8.4.1).
    public let token = "gzip"

    /// Creates the encoder.
    public init() {
        // Stateless.
    }

    /// Encodes `body` as a gzip member, or `nil` for an empty body (nothing to encode).
    public func encode(_ body: [UInt8]) -> [UInt8]? {
        Gzip.compress(body)
    }

    /// An incremental gzip member, on every build.
    ///
    /// `ContentEncoderStreamTests` asserts the buffered and streamed availabilities agree — the
    /// two entry points must never disagree. A coding that could encode but not stream
    /// would serve streamed responses **uncoded** (never buffered and coded — see
    /// ``StreamingContentEncoder``), which is a silent downgrade for exactly the bodies most
    /// worth coding: SSE, chunked downloads, and every static file over the streaming threshold.
    /// Darwin streams through `compression_stream`, everywhere else through the in-house
    /// ``GzipDeflator``; each is byte-identical to its own platform's buffered path.
    public func makeStream() -> (any ContentEncoderStream)? {
        GzipEncoderStream()
    }
}
